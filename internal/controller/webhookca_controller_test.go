package controller

import (
	"context"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
)

func webhookScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	_ = honeypodv1alpha1.AddToScheme(s)
	_ = admissionregistrationv1.AddToScheme(s)
	return s
}

// TestWebhookCABundle_RepatchesDrift covers the self-heal: a webhook config
// whose caBundle was cleared (recreated, re-applied) is re-patched to the
// manager's CA on reconcile.
func TestWebhookCABundle_RepatchesDrift(t *testing.T) {
	requireEnvtest(t)
	ca := []byte("THE-CA-PEM")
	cfg := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "honeypod-pod-join"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{Name: "podjoin.honeypod.io", ClientConfig: admissionregistrationv1.WebhookClientConfig{CABundle: nil}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(webhookScheme(t)).WithObjects(cfg).Build()
	r := &WebhookCABundleReconciler{Client: c, ConfigName: "honeypod-pod-join", CABundle: ca}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "honeypod-pod-join"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got admissionregistrationv1.MutatingWebhookConfiguration
	if err := c.Get(context.Background(), types.NamespacedName{Name: "honeypod-pod-join"}, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Webhooks[0].ClientConfig.CABundle) != "THE-CA-PEM" {
		t.Fatalf("expected the caBundle re-patched to the CA, got %q", got.Webhooks[0].ClientConfig.CABundle)
	}
}

// TestWebhookCABundle_IgnoresOtherConfigs confirms it never touches a
// different admission webhook.
func TestWebhookCABundle_IgnoresOtherConfigs(t *testing.T) {
	requireEnvtest(t)
	other := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "someone-elses-webhook"},
		Webhooks:   []admissionregistrationv1.MutatingWebhook{{Name: "x", ClientConfig: admissionregistrationv1.WebhookClientConfig{CABundle: []byte("theirs")}}},
	}
	c := fake.NewClientBuilder().WithScheme(webhookScheme(t)).WithObjects(other).Build()
	r := &WebhookCABundleReconciler{Client: c, ConfigName: "honeypod-pod-join", CABundle: []byte("ours")}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "someone-elses-webhook"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got admissionregistrationv1.MutatingWebhookConfiguration
	_ = c.Get(context.Background(), types.NamespacedName{Name: "someone-elses-webhook"}, &got)
	if string(got.Webhooks[0].ClientConfig.CABundle) != "theirs" {
		t.Fatal("must not modify a webhook config it does not own")
	}
}
