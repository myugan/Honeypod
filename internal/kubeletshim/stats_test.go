package kubeletshim

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func statsShim(t *testing.T) *Shim {
	t.Helper()
	started := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	objs := []runtime.Object{
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-api", Namespace: "billing"},
			Spec:       corev1.PodSpec{NodeName: "node-1", Containers: []corev1.Container{{Name: "app", Image: "nginx:1"}}},
			Status:     corev1.PodStatus{StartTime: &started},
		},
		// An unbound pod (no nodeName) must be excluded -- the kubelet only
		// reports pods it runs.
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "billing"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx:1"}}},
		},
	}
	return &Shim{client: fake.NewSimpleClientset(objs...)}
}

// TestResourceMetrics_ScrapeShape proves /metrics/resource emits the node and
// per-container CPU/memory series metrics-server needs, with timestamps, and
// only for bound pods.
func TestResourceMetrics_ScrapeShape(t *testing.T) {
	sh := statsShim(t)
	rec := httptest.NewRecorder()
	sh.handleResourceMetrics(rec, httptest.NewRequest("GET", "/metrics/resource", nil))

	body := rec.Body.String()
	for _, want := range []string{
		"node_cpu_usage_seconds_total ",
		"node_memory_working_set_bytes ",
		`container_cpu_usage_seconds_total{container="app",namespace="billing",pod="checkout-api"}`,
		`container_memory_working_set_bytes{container="app",namespace="billing",pod="checkout-api"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("resource metrics missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `pod="pending"`) {
		t.Error("unbound pod must not appear in kubelet stats")
	}
}

// TestStatsSummary_Shape proves /stats/summary returns node + pod usage JSON.
func TestStatsSummary_Shape(t *testing.T) {
	sh := statsShim(t)
	rec := httptest.NewRecorder()
	sh.handleStatsSummary(rec, httptest.NewRequest("GET", "/stats/summary", nil))
	body := rec.Body.String()
	for _, want := range []string{`"node"`, `"usageNanoCores"`, `"workingSetBytes"`, `"checkout-api"`, `"billing"`} {
		if !strings.Contains(body, want) {
			t.Errorf("summary missing %q:\n%s", want, body)
		}
	}
}
