package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
)

func singleDecoyScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := honeypodv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestResolveJoinAnnotation_SingleDecoyCrossNamespace proves a "true" pod in
// ANY namespace relays to the sole cluster-wide decoy -- the single-decoy
// deployment shape -- while an explicit target is unaffected.
func TestResolveJoinAnnotation_SingleDecoyCrossNamespace(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{ObjectMeta: metav1.ObjectMeta{Name: "the-decoy", Namespace: "honeypod"}}
	c := fake.NewClientBuilder().WithScheme(singleDecoyScheme(t)).WithObjects(kt).Build()

	// "true" from a totally different namespace resolves to the one decoy.
	ns, name, ok := resolveJoinAnnotation(testCtx, c, "team-a", joinAnnotationImplicit)
	if !ok || ns != "honeypod" || name != "the-decoy" {
		t.Fatalf("expected the sole decoy (honeypod/the-decoy), got (%s, %s, %v)", ns, name, ok)
	}

	// A second Decoy removes the single-decoy shortcut: "true" from a
	// namespace with no Decoy no longer resolves.
	kt2 := &honeypodv1alpha1.Decoy{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "other"}}
	c2 := fake.NewClientBuilder().WithScheme(singleDecoyScheme(t)).WithObjects(kt, kt2).Build()
	if _, _, ok := resolveJoinAnnotation(testCtx, c2, "team-a", joinAnnotationImplicit); ok {
		t.Fatal("with two Decoys, a foreign-namespace true must not resolve")
	}
}

// TestListJoinedPods_SingleDecoyCrossNamespace proves the reconciler joins a
// "true" pod from another namespace to the sole cluster-wide decoy.
func TestListJoinedPods_SingleDecoyCrossNamespace(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{ObjectMeta: metav1.ObjectMeta{Name: "the-decoy", Namespace: "honeypod"}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "bait", Namespace: "team-a", Annotations: map[string]string{joinAnnotation: joinAnnotationImplicit}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "x:1"}}},
	}
	c := fake.NewClientBuilder().WithScheme(singleDecoyScheme(t)).WithObjects(kt, pod).Build()
	r := &DecoyReconciler{Client: c, Scheme: singleDecoyScheme(t)}

	joined, err := r.listJoinedPods(testCtx, kt)
	if err != nil {
		t.Fatalf("listJoinedPods: %v", err)
	}
	if len(joined) != 1 || joined[0].Name != "bait" || joined[0].Namespace != "team-a" {
		t.Fatalf("expected the cross-namespace bait pod joined to the sole decoy, got %+v", joined)
	}
}
