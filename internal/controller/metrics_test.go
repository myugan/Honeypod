package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"honeypod.io/honeypod/internal/metrics"
)

// TestReconcile_RecordsMetrics drives a real reconcile against envtest and
// verifies the resource-state metrics track the Decoy through its life:
// phase gauge set one-hot after reconcile, joined-pods gauge counting
// annotated Pods, and every per-Decoy series dropped once the Decoy
// is deleted and the not-found reconcile has run.
func TestReconcile_RecordsMetrics(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "metrics-trap")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}

	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// No Deployment controller runs in envtest, so the decoy never reports
	// ready replicas: the phase must be Pending, one-hot.
	for phase, want := range map[string]float64{"Pending": 1, "Ready": 0, "Failed": 0} {
		if got := testutil.ToFloat64(metrics.Phase.WithLabelValues(ns, kt.Name, phase)); got != want {
			t.Errorf("honeypod_phase{phase=%q} = %v, want %v", phase, got, want)
		}
	}
	if got := testutil.ToFloat64(metrics.JoinedPods.WithLabelValues(ns, kt.Name)); got != 0 {
		t.Errorf("honeypod_joined_pods = %v, want 0", got)
	}

	// Join a Pod and reconcile again: the gauge must follow.
	pod := &corev1.Pod{}
	pod.Name = "joined-pod"
	pod.Namespace = ns
	pod.Annotations = map[string]string{joinAnnotation: ns + "/" + kt.Name}
	pod.Spec.Containers = []corev1.Container{{Name: "app", Image: "app:1"}}
	if err := k8sClient.Create(testCtx, pod); err != nil {
		t.Fatalf("creating joined pod: %v", err)
	}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile after join: %v", err)
	}
	if got := testutil.ToFloat64(metrics.JoinedPods.WithLabelValues(ns, kt.Name)); got != 1 {
		t.Errorf("honeypod_joined_pods after join = %v, want 1", got)
	}

	// Delete the Decoy; the not-found reconcile must drop every series.
	if err := k8sClient.Delete(testCtx, kt); err != nil {
		t.Fatalf("deleting Decoy: %v", err)
	}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile after delete: %v", err)
	}
	match := prometheus.Labels{"namespace": ns, "name": kt.Name}
	if n := metrics.Phase.DeletePartialMatch(match); n != 0 {
		t.Errorf("honeypod_phase: %d series survived Decoy deletion", n)
	}
	if n := metrics.JoinedPods.DeletePartialMatch(match); n != 0 {
		t.Errorf("honeypod_joined_pods: %d series survived Decoy deletion", n)
	}
}

// failingSecretClient fails every Secret create, to force a reconcile error
// deterministically without touching anything else about the flow.
type failingSecretClient struct {
	client.Client
}

func (f *failingSecretClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, isSecret := obj.(*corev1.Secret); isSecret {
		return fmt.Errorf("injected secret-create failure")
	}
	return f.Client.Create(ctx, obj, opts...)
}

// TestReconcile_ErrorIncrementsErrorMetric proves a failed reconcile bumps
// honeypod_reconcile_errors_total for that specific Decoy and marks its
// phase Failed one-hot.
func TestReconcile_ErrorIncrementsErrorMetric(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "metrics-err-trap")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	defer metrics.DeleteDecoy(ns, kt.Name)

	r := &DecoyReconciler{Client: &failingSecretClient{Client: k8sClient}, Scheme: newReconciler().Scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}

	before := testutil.ToFloat64(metrics.ReconcileErrors.WithLabelValues(ns, kt.Name))
	if _, err := r.Reconcile(testCtx, req); err == nil {
		t.Fatal("reconcile succeeded despite injected secret-create failure")
	}
	after := testutil.ToFloat64(metrics.ReconcileErrors.WithLabelValues(ns, kt.Name))
	if after != before+1 {
		t.Errorf("honeypod_reconcile_errors_total: got %v, want %v", after, before+1)
	}
	if got := testutil.ToFloat64(metrics.Phase.WithLabelValues(ns, kt.Name, "Failed")); got != 1 {
		t.Errorf("honeypod_phase{phase=Failed} after failed reconcile = %v, want 1", got)
	}
}
