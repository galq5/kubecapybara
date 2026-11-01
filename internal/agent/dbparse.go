package agent

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// database protocols identified by the L7 eBPF program
const (
	protoHTTP     = 1
	protoPostgres = 2
	protoRedis    = 3
	protoMySQL    = 4
)

var protoNames = map[uint8]string{protoPostgres: "postgres", protoRedis: "redis", protoMySQL: "mysql"}

var (
	sqlString = regexp.MustCompile(`'(?:[^']|'')*'?`)
	sqlNumber = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	sqlSpace  = regexp.MustCompile(`\s+`)
	sqlIn     = regexp.MustCompile(`(?i)\bIN\s*\(\s*\?(?:\s*,\s*\?)*\s*\)`)
)

// NormalizeSQL replaces literals with ? so statements aggregate by shape.
func NormalizeSQL(q string) string {
	q = sqlString.ReplaceAllString(q, "?")
	q = sqlNumber.ReplaceAllString(q, "?")
	q = sqlIn.ReplaceAllString(q, "IN (?)")
	q = strings.TrimSpace(sqlSpace.ReplaceAllString(q, " "))
	if len(q) > 100 {
		q = q[:100] + "…"
	}
	if q == "" {
		q = "(empty)"
	}
	return q
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// ParseDBRequest extracts a normalized statement (or command) from the first
// bytes of a client request.
func ParseDBRequest(proto uint8, b []byte) string {
	switch proto {
	case protoPostgres:
		if len(b) < 6 {
			return "(unknown)"
		}
		body := b[5:]
		switch b[0] {
		case 'Q':
			return NormalizeSQL(cstring(body))
		case 'P': // Parse: statement name \0 query \0
			if i := bytes.IndexByte(body, 0); i >= 0 {
				return NormalizeSQL(cstring(body[i+1:]))
			}
		case 'B':
			return "(execute prepared statement)"
		}
	case protoMySQL:
		if len(b) > 5 {
			return NormalizeSQL(cstring(b[5:]))
		}
	case protoRedis:
		return redisCommand(b)
	}
	return "(unknown)"
}

// redisCommand returns the command name (and subcommand for a few) of a RESP
// array request: "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n" -> "GET".
func redisCommand(b []byte) string {
	parts := strings.Split(string(b), "\r\n")
	if len(parts) < 3 || !strings.HasPrefix(parts[1], "$") {
		return "(unknown)"
	}
	cmd := strings.ToUpper(parts[2])
	switch cmd {
	case "CLIENT", "CONFIG", "CLUSTER", "XGROUP", "SCRIPT", "OBJECT":
		if len(parts) >= 5 {
			cmd += " " + strings.ToUpper(parts[4])
		}
	}
	if len(cmd) > 40 {
		cmd = cmd[:40]
	}
	return cmd
}

// DBError reports whether the first bytes of a reply carry an error.
func DBError(proto uint8, resp []byte) bool {
	if len(resp) == 0 {
		return false
	}
	switch proto {
	case protoPostgres:
		return resp[0] == 'E'
	case protoRedis:
		return resp[0] == '-'
	case protoMySQL:
		// 3 byte length, sequence id, then 0xff for ERR packets
		return len(resp) > 4 && resp[4] == 0xff
	}
	return false
}

func dbKey(proto uint8, q string) string { return strconv.Itoa(int(proto)) + "|" + q }
