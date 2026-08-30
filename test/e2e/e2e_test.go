//go:build e2e

// Package e2e holds end-to-end tests that start the real controller manager
// against an envtest apiserver and drive a Decoy through its lifecycle the
// way the running operator would. They are build-tagged so the default
// `go test ./...` stays fast. Run them with:
//
//	go test -tags e2e ./test/e2e/...
//
// They need the same envtest binaries as the controller integration tests
// (KUBEBUILDER_ASSETS). They do not cover a real node, so image pulls, live
// exec, and NetworkPolicy enforcement are out of scope and need a real
// cluster.
package e2e

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/controller"
)

// TestDecoyReachesReadyThroughTheManager creates a Decoy against a running
// manager and asserts the operator reconciles it to Ready, exercising the
// SetupWithManager wiring (watches, owner-reference requeues, status writes)
// that the per-reconcile unit tests call around rather than through.
func TestDecoyReachesReadyThroughTheManager(t *testing.T) {
	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("starting envtest: %v", err)
	}
	defer func() { _ = testEnv.Stop() }()

	scheme := clientgoscheme.Scheme
	if err := honeypodv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding to scheme: %v", err)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:         scheme,
		Metrics:        metricsserver.Options{BindAddress: "0"},
		LeaderElection: false,
	})
	if err != nil {
		t.Fatalf("creating manager: %v", err)
	}
	if err := (&controller.DecoyReconciler{
		Client:                 mgr.GetClient(),
		ManagerAuditWebhookURL: "http://127.0.0.1:1/audit",
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setting up reconciler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgrDone := make(chan error, 1)
	go func() { mgrDone <- mgr.Start(ctx) }()

	// A direct client for setup and assertions, independent of the manager
	// cache so reads never race a cache sync.
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "e2e-honeypod"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatalf("creating namespace: %v", err)
	}
	kt := &honeypodv1alpha1.Decoy{
		ObjectMeta: metav1.ObjectMeta{Name: "shopwave", Namespace: ns.Name},
		Spec:       honeypodv1alpha1.DecoySpec{FakeNodes: []honeypodv1alpha1.FakeNode{{Name: "node-1"}}},
	}
	if err := c.Create(ctx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	key := types.NamespacedName{Namespace: ns.Name, Name: kt.Name}

	// The manager should reconcile the new Decoy and create its Deployment.
	var dep appsv1.Deployment
	waitFor(t, 30*time.Second, "deployment created by the manager", func() bool {
		return c.Get(ctx, key, &dep) == nil
	})

	// Simulate the Deployment becoming ready (no kubelet under envtest).
	dep.Status.ReadyReplicas = 1
	dep.Status.Replicas = 1
	if err := c.Status().Update(ctx, &dep); err != nil {
		t.Fatalf("simulating deployment readiness: %v", err)
	}

	// Owning the Deployment, the manager should observe that and flip Ready.
	var got honeypodv1alpha1.Decoy
	waitFor(t, 30*time.Second, "decoy phase Ready", func() bool {
		if err := c.Get(ctx, key, &got); err != nil {
			return false
		}
		return got.Status.Phase == honeypodv1alpha1.DecoyPhaseReady && got.Status.CredentialsSecret != ""
	})

	// The credentials Secret it named must exist and carry a kubeconfig.
	var sec corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns.Name, Name: got.Status.CredentialsSecret}, &sec); err != nil {
		t.Fatalf("credentials secret %q not found: %v", got.Status.CredentialsSecret, err)
	}
	if len(sec.Data["kubeconfig"]) == 0 {
		t.Fatal("credentials secret has no kubeconfig")
	}

	cancel()
	select {
	case err := <-mgrDone:
		if err != nil {
			t.Fatalf("manager exited with error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("manager did not shut down in time")
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
