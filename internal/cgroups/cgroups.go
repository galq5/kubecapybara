// Package cgroups maps cgroup v2 IDs (as returned by bpf_get_current_cgroup_id)
// to Kubernetes pods and containers by walking the cgroup filesystem.
package cgroups

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	podRe       = regexp.MustCompile(`pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)
	containerRe = regexp.MustCompile(`^(?:cri-containerd-|crio-|docker-|containerd-|libpod-)?([0-9a-f]{64})(?:\.scope)?$`)
)

// Info describes one cgroup.
type Info struct {
	ID          uint64
	Path        string // relative to the cgroup2 root, starting with "/"
	PodUID      string
	PodPath     string // pod-level cgroup path (relative), if PodUID != ""
	ContainerID string
	Entity      string // "pod:<uid>" or "host:<path>"
	Created     time.Time
}

// ParsePath extracts pod UID, container ID and the pod-level path from a
// cgroup path. Works for both systemd and cgroupfs drivers and nested
// (kind/docker) layouts.
func ParsePath(p string) (podUID, containerID, podPath string) {
	loc := podRe.FindStringSubmatchIndex(p)
	if loc != nil {
		podUID = strings.ReplaceAll(p[loc[2]:loc[3]], "_", "-")
		end := strings.IndexByte(p[loc[1]:], '/')
		if end < 0 {
			podPath = p
		} else {
			podPath = p[:loc[1]+end]
		}
	}
	base := filepath.Base(p)
	if m := containerRe.FindStringSubmatch(base); m != nil {
		containerID = m[1]
	}
	return
}

// EntityFor returns the entity ID for a cgroup path.
func EntityFor(p string) string {
	if uid, _, _ := ParsePath(p); uid != "" {
		return "pod:" + uid
	}
	if p == "" {
		p = "/"
	}
	return "host:" + p
}

// Resolver resolves cgroup IDs. It is safe for concurrent use.
type Resolver struct {
	root string

	mu       sync.RWMutex
	byID     map[uint64]*Info
	unknown  map[uint64]time.Time // ids a rescan did not find (deleted cgroups)
	lastScan time.Time
	minScan  time.Duration
}

// negativeTTL is how long an id that a rescan did not find is not rescanned
// for again (cgroups of exited containers keep showing up in events).
const negativeTTL = 30 * time.Second

// DetectRoot finds the cgroup v2 mount point under prefix (e.g. "" or "/host").
func DetectRoot(prefix string) (string, error) {
	candidates := []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"}
	for _, c := range candidates {
		p := filepath.Join(prefix, c)
		if _, err := os.Stat(filepath.Join(p, "cgroup.controllers")); err == nil {
			return p, nil
		}
	}
	// fall back to mountinfo
	f, err := os.Open("/proc/self/mountinfo")
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			for i, fld := range fields {
				if fld == "-" && i+1 < len(fields) && fields[i+1] == "cgroup2" {
					return fields[4], nil
				}
			}
		}
	}
	return "", fmt.Errorf("no cgroup v2 hierarchy found (looked in %v under %q)", candidates, prefix)
}

// NewResolver creates a resolver rooted at the cgroup2 mount point.
func NewResolver(root string) *Resolver {
	r := &Resolver{root: root, byID: map[uint64]*Info{}, unknown: map[uint64]time.Time{}, minScan: 2 * time.Second}
	r.Scan()
	return r
}

// Root returns the cgroup2 mount point.
func (r *Resolver) Root() string { return r.root }

// Scan walks the hierarchy and refreshes the ID map.
func (r *Resolver) Scan() {
	byID := map[uint64]*Info{}
	_ = filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		rel := strings.TrimPrefix(path, r.root)
		if rel == "" {
			rel = "/"
		}
		uid, cid, podPath := ParsePath(rel)
		info := &Info{
			ID:          st.Ino,
			Path:        rel,
			PodUID:      uid,
			PodPath:     podPath,
			ContainerID: cid,
			Created:     time.Unix(st.Ctim.Sec, st.Ctim.Nsec),
		}
		if uid != "" {
			info.Entity = "pod:" + uid
		} else {
			info.Entity = "host:" + rel
		}
		byID[st.Ino] = info
		return nil
	})
	r.mu.Lock()
	r.byID = byID
	r.lastScan = time.Now()
	for id := range r.unknown {
		if _, ok := byID[id]; ok {
			delete(r.unknown, id)
		}
	}
	r.mu.Unlock()
}

// Lookup resolves an ID, rescanning (rate limited) when it is unknown.
// It never returns nil.
func (r *Resolver) Lookup(id uint64) *Info {
	r.mu.RLock()
	info, ok := r.byID[id]
	last := r.lastScan
	missAt, missed := r.unknown[id]
	r.mu.RUnlock()
	if ok {
		return info
	}
	if id != 0 && time.Since(last) > r.minScan && (!missed || time.Since(missAt) > negativeTTL) {
		r.Scan()
		r.mu.Lock()
		info, ok = r.byID[id]
		if !ok {
			if len(r.unknown) > 10000 {
				r.unknown = map[uint64]time.Time{}
			}
			r.unknown[id] = time.Now()
		}
		r.mu.Unlock()
		if ok {
			return info
		}
	}
	return &Info{ID: id, Entity: fmt.Sprintf("cg:%d", id)}
}

// Entity is a shorthand for Lookup(id).Entity.
func (r *Resolver) Entity(id uint64) string { return r.Lookup(id).Entity }

// Pods returns pod UID -> absolute pod-level cgroup directory.
func (r *Resolver) Pods() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string]string{}
	for _, info := range r.byID {
		if info.PodUID != "" {
			out[info.PodUID] = filepath.Join(r.root, info.PodPath)
		}
	}
	return out
}

// Paths returns the cgroup paths (relative to the root) found by the last scan.
func (r *Resolver) Paths() map[string]bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]bool, len(r.byID))
	for _, info := range r.byID {
		out[info.Path] = true
	}
	return out
}

// IDsForEntity returns all cgroup IDs (pod and container level) of an entity.
func (r *Resolver) IDsForEntity(entity string) []uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var ids []uint64
	for id, info := range r.byID {
		if info.Entity == entity {
			ids = append(ids, id)
		}
	}
	return ids
}

// Containers returns container ID -> entity for all known containers.
func (r *Resolver) Containers() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string]string{}
	for _, info := range r.byID {
		if info.ContainerID != "" {
			out[info.ContainerID] = info.Entity
		}
	}
	return out
}

// HostPath converts a cgroup path read from /proc/<pid>/cgroup inside a
// private cgroup namespace (e.g. "/../../kubepods.slice/x") into the path
// relative to the host cgroup2 root ("/kubepods.slice/x").
func HostPath(p string) string {
	for strings.HasPrefix(p, "/..") {
		p = strings.TrimPrefix(p, "/..")
	}
	if p == "" {
		return "/"
	}
	return p
}

// ProcCgroupID returns the cgroup v2 ID of a process by reading
// /proc/<pid>/cgroup and stat'ing the directory.
func (r *Resolver) ProcCgroupID(procRoot string, pid uint32) (uint64, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, fmt.Sprint(pid), "cgroup"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::") {
			p := HostPath(strings.TrimPrefix(line, "0::"))
			var st syscall.Stat_t
			if err := syscall.Stat(filepath.Join(r.root, p), &st); err != nil {
				return 0, err
			}
			return st.Ino, nil
		}
	}
	return 0, fmt.Errorf("no cgroup v2 entry for pid %d", pid)
}
