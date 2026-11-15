package client

import (
	"context"
	"strings"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type secretToken struct {
	mu    sync.Mutex
	value string
}

func (t *secretToken) get(ctx context.Context, cs kubernetes.Interface, namespace, name string) string {
	if cs == nil || name == "" {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.value == "" && ctx.Err() == nil {
		if s, err := cs.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
			t.value = strings.TrimSpace(string(s.Data["token"]))
		}
	}
	return t.value
}

// invalidate only clears the token actually rejected by the server.
func (t *secretToken) invalidate(rejected string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.value == rejected {
		t.value = ""
	}
}
