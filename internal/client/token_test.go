package client

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretTokenRecoversAfterFailureAndRotation(t *testing.T) {
	cs := fake.NewSimpleClientset()
	ctx := context.Background()
	clock := time.Unix(1000, 0)
	cache := secretToken{now: func() time.Time { return clock }}
	if token := cache.get(ctx, cs, "agent", "auth"); token != "" {
		t.Fatal("absent Secret returned a token")
	}
	gets := func() int {
		n := 0
		for _, a := range cs.Actions() {
			if a.GetVerb() == "get" && a.GetResource().Resource == "secrets" {
				n++
			}
		}
		return n
	}
	for i := 0; i < 10; i++ {
		cache.get(ctx, cs, "agent", "auth")
	}
	if n := gets(); n != 1 {
		t.Fatalf("missing Secret looked up %d times instead of once", n)
	}
	secrets := cs.CoreV1().Secrets("agent")
	obj, err := secrets.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "auth"},
		Data: map[string][]byte{"token": []byte("initial")}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if token := cache.get(ctx, cs, "agent", "auth"); token != "" {
		t.Fatal("failed lookup retried before tokenRetry")
	}
	clock = clock.Add(tokenRetry)
	if token := cache.get(ctx, cs, "agent", "auth"); token != "initial" {
		t.Fatal("lookup did not recover after the Secret was created")
	}
	obj.Data["token"] = []byte("rotated")
	if _, err := secrets.Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	cache.invalidate("initial")
	if token := cache.get(ctx, cs, "agent", "auth"); token != "rotated" {
		t.Fatal("rejected token was not refreshed")
	}
	cache.invalidate("initial")
	if cache.value != "rotated" {
		t.Fatal("late rejection invalidated the refreshed token")
	}
}
