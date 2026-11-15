package client

import (
	"context"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// tokenRetry is how long a failed Secret lookup is remembered. A missing or
// forbidden Secret is the normal case for agents without authentication, so
// it must not cost an API call per agent request.
var tokenRetry = 30 * time.Second

type secretToken struct {
	mu       sync.Mutex
	value    string
	failedAt time.Time
	now      func() time.Time // for tests
}

func (t *secretToken) get(ctx context.Context, cs kubernetes.Interface, namespace, name string) string {
	if cs == nil || name == "" {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now
	if t.now != nil {
		now = t.now
	}
	if t.value != "" || ctx.Err() != nil || (!t.failedAt.IsZero() && now().Sub(t.failedAt) < tokenRetry) {
		return t.value
	}
	s, err := cs.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		t.value = strings.TrimSpace(string(s.Data["token"]))
	}
	if t.value == "" && ctx.Err() == nil {
		t.failedAt = now()
	} else {
		t.failedAt = time.Time{}
	}
	return t.value
}

// invalidate only clears the token actually rejected by the server. The next
// request reads the Secret again right away (the token may have rotated).
func (t *secretToken) invalidate(rejected string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.value == rejected {
		t.value = ""
		t.failedAt = time.Time{}
	}
}
