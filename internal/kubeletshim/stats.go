package kubeletshim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The kubelet stats API. The shim is the kubelet for this nested cluster, so
// it serves the same endpoints a real kubelet does -- /stats/summary,
// /metrics/resource (what metrics-server scrapes), and /pods -- rather than
// 404ing them. No real container runs behind a fake pod, so the usage numbers
// are synthesized, but they are stable, plausible, and in the exact wire
// shape a real kubelet emits, so a real metrics-server can scrape them and
// `kubectl top` returns data.

// containerCPUCores is a container's steady CPU use in cores (0.005-0.025).
func containerCPUCores(key string) float64 {
	return 0.005 + float64(hash32(key)%20)/1000.0
}

// containerMemBytes is a container's working-set memory (16-256 MiB).
func containerMemBytes(key string) int64 {
	return (16 + int64(hash32(key)%240)) * 1024 * 1024
}

// podStartOrNow returns a pod's start time for cumulative counters, defaulting
// to now for a pod without one.
func podStartOrNow(p *corev1.Pod) time.Time {
	if p.Status.StartTime != nil && !p.Status.StartTime.IsZero() {
		return p.Status.StartTime.Time
	}
	if !p.CreationTimestamp.IsZero() {
		return p.CreationTimestamp.Time
	}
	return time.Now()
}

// listNodePods returns the pods this kubelet "runs": every pod bound to a
// node (all seeded/adopted pods report a nodeName). The kubelet stats
// endpoints aren't node-scoped in their path, so one shim serves them for
// whichever fake node the apiserver proxied the request to.
func (sh *Shim) listNodePods(ctx context.Context) (*corev1.PodList, error) {
	var out corev1.PodList
	all, err := sh.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for i := range all.Items {
		if all.Items[i].Spec.NodeName != "" {
			out.Items = append(out.Items, all.Items[i])
		}
	}
	return &out, nil
}

// handleResourceMetrics serves /metrics/resource in the Prometheus text
// format metrics-server scrapes: node and per-container CPU (a
// seconds-total counter) and working-set memory (a gauge), each with a
// millisecond timestamp.
func (sh *Shim) handleResourceMetrics(w http.ResponseWriter, r *http.Request) {
	pods, err := sh.listNodePods(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	now := time.Now()
	tsMS := now.UnixMilli()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	var nodeCPU float64
	var nodeMem int64
	var b []byte
	b = append(b, "# TYPE container_cpu_usage_seconds_total counter\n"...)
	cpuLines := []byte{}
	memLines := []byte("# TYPE container_memory_working_set_bytes gauge\n")
	for i := range pods.Items {
		p := &pods.Items[i]
		since := podStartOrNow(p)
		for _, c := range p.Spec.Containers {
			key := p.Namespace + "/" + p.Name + "/" + c.Name
			cores := containerCPUCores(key)
			cpuSec := now.Sub(since).Seconds() * cores
			mem := containerMemBytes(key)
			nodeCPU += cpuSec
			nodeMem += mem
			cpuLines = append(cpuLines, fmt.Sprintf("container_cpu_usage_seconds_total{container=%q,namespace=%q,pod=%q} %.6f %d\n",
				c.Name, p.Namespace, p.Name, cpuSec, tsMS)...)
			memLines = append(memLines, fmt.Sprintf("container_memory_working_set_bytes{container=%q,namespace=%q,pod=%q} %d %d\n",
				c.Name, p.Namespace, p.Name, mem, tsMS)...)
		}
	}
	// A real node's own overhead on top of the pods'.
	nodeCPU += 0.15
	nodeMem += 1500 * 1024 * 1024

	b = append(b, cpuLines...)
	b = append(b, memLines...)
	b = append(b, fmt.Sprintf("# TYPE node_cpu_usage_seconds_total counter\nnode_cpu_usage_seconds_total %.6f %d\n", nodeCPU, tsMS)...)
	b = append(b, fmt.Sprintf("# TYPE node_memory_working_set_bytes gauge\nnode_memory_working_set_bytes %d %d\n", nodeMem, tsMS)...)
	_, _ = w.Write(b)
}

// handleStatsSummary serves /stats/summary, the older Summary JSON some
// tooling (and `kubectl get --raw .../stats/summary`) still reads. Built by
// hand to avoid importing the heavy kubelet stats-api package for one shape.
func (sh *Shim) handleStatsSummary(w http.ResponseWriter, r *http.Request) {
	pods, err := sh.listNodePods(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	now := time.Now()
	nowStr := now.UTC().Format(time.RFC3339)

	var nodeCPUNanoCores int64
	var nodeMem int64
	podStats := make([]map[string]any, 0, len(pods.Items))
	for i := range pods.Items {
		p := &pods.Items[i]
		since := podStartOrNow(p)
		containers := make([]map[string]any, 0, len(p.Spec.Containers))
		for _, c := range p.Spec.Containers {
			key := p.Namespace + "/" + p.Name + "/" + c.Name
			cores := containerCPUCores(key)
			nano := int64(cores * 1e9)
			mem := containerMemBytes(key)
			nodeCPUNanoCores += nano
			nodeMem += mem
			containers = append(containers, map[string]any{
				"name": c.Name,
				"cpu": map[string]any{
					"time":                 nowStr,
					"usageNanoCores":       nano,
					"usageCoreNanoSeconds": int64(now.Sub(since).Seconds() * cores * 1e9),
				},
				"memory": map[string]any{"time": nowStr, "workingSetBytes": mem},
			})
		}
		podStats = append(podStats, map[string]any{
			"podRef":     map[string]any{"name": p.Name, "namespace": p.Namespace, "uid": string(p.UID)},
			"startTime":  since.UTC().Format(time.RFC3339),
			"containers": containers,
		})
	}
	nodeCPUNanoCores += 150 * 1e6 // node overhead
	nodeMem += 1500 * 1024 * 1024

	summary := map[string]any{
		"node": map[string]any{
			"nodeName": sh.firstNodeName(),
			"cpu":      map[string]any{"time": nowStr, "usageNanoCores": nodeCPUNanoCores},
			"memory":   map[string]any{"time": nowStr, "workingSetBytes": nodeMem},
		},
		"pods": podStats,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

// handlePodsEndpoint serves /pods, the kubelet's own view of the pods it
// runs -- a v1.PodList, exactly what a real kubelet returns.
func (sh *Shim) handlePodsEndpoint(w http.ResponseWriter, r *http.Request) {
	pods, err := sh.listNodePods(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	pods.Kind = "PodList"
	pods.APIVersion = "v1"
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pods)
}

// firstNodeName returns a seeded node name for the summary's nodeName field.
func (sh *Shim) firstNodeName() string {
	if s := sh.currentSeed(); s != nil && len(s.FakeNodes) > 0 {
		return s.FakeNodes[0].Name
	}
	return ""
}
