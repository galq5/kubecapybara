package client

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretTokenRecoversAfterFailureAndRotation(t *testing.T) {
	cs := fake.NewSimpleClientset()
	ctx := context.Background()
	var cache secretToken
	if token := cache.get(ctx, cs, "agent", "auth"); token != "" {
		t.Fatal("absent Secret returned a token")
	}
	secrets := cs.CoreV1().Secrets("agent")
	obj, err := secrets.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "auth"},
		Data: map[string][]byte{"token": []byte("initial")}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
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
