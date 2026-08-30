package kubeletshim

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"honeypod.io/honeypod/internal/seed"
)

// createControllers upserts the owning objects (Deployment, ReplicaSet,
// DaemonSet) the seed lists for the kube-system components, so a seeded
// pod's ownerReference resolves to a real object under `kubectl describe`
// and `get rs|ds|deploy`. Each object's assigned UID is recorded in
// objectUIDs so the pods that reference it carry the same UID.
//
// The seed lists a controller before anything that references it (a
// Deployment before its ReplicaSet), so processing in order lets a later
// object's ownerReference resolve to the earlier one's real UID.
func (sh *Shim) createControllers(ctx context.Context, controllers []seed.Controller) error {
	for _, c := range controllers {
		meta := metav1.ObjectMeta{
			Name:            c.Name,
			Namespace:       c.Namespace,
			Labels:          c.Labels,
			OwnerReferences: sh.resolveOwnerRefs(c.OwnerRefs),
		}
		selector := &metav1.LabelSelector{MatchLabels: c.Labels}
		template := corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: c.Labels},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: c.Name, Image: c.Image}}},
		}
		replicas := c.Replicas

		var uid string
		var kindName = c.Kind + "/" + c.Name
		switch c.Kind {
		case "Deployment":
			obj := &appsv1.Deployment{ObjectMeta: meta, Spec: appsv1.DeploymentSpec{
				Replicas: &replicas, Selector: selector, Template: template,
			}}
			out, err := sh.upsertDeployment(ctx, obj)
			if err != nil {
				return err
			}
			out.Status = appsv1.DeploymentStatus{Replicas: replicas, ReadyReplicas: replicas, AvailableReplicas: replicas, UpdatedReplicas: replicas}
			out, _ = sh.client.AppsV1().Deployments(c.Namespace).UpdateStatus(ctx, out, metav1.UpdateOptions{})
			uid = string(out.UID)
		case "ReplicaSet":
			obj := &appsv1.ReplicaSet{ObjectMeta: meta, Spec: appsv1.ReplicaSetSpec{
				Replicas: &replicas, Selector: selector, Template: template,
			}}
			out, err := sh.upsertReplicaSet(ctx, obj)
			if err != nil {
				return err
			}
			out.Status = appsv1.ReplicaSetStatus{Replicas: replicas, ReadyReplicas: replicas, AvailableReplicas: replicas}
			out, _ = sh.client.AppsV1().ReplicaSets(c.Namespace).UpdateStatus(ctx, out, metav1.UpdateOptions{})
			uid = string(out.UID)
		case "DaemonSet":
			obj := &appsv1.DaemonSet{ObjectMeta: meta, Spec: appsv1.DaemonSetSpec{
				Selector: selector, Template: template,
			}}
			out, err := sh.upsertDaemonSet(ctx, obj)
			if err != nil {
				return err
			}
			out.Status = appsv1.DaemonSetStatus{
				DesiredNumberScheduled: replicas, CurrentNumberScheduled: replicas,
				NumberReady: replicas, NumberAvailable: replicas, UpdatedNumberScheduled: replicas,
			}
			out, _ = sh.client.AppsV1().DaemonSets(c.Namespace).UpdateStatus(ctx, out, metav1.UpdateOptions{})
			uid = string(out.UID)
		default:
			continue
		}
		sh.objectUIDs[kindName] = types.UID(uid)
	}
	return nil
}

func (sh *Shim) upsertDeployment(ctx context.Context, d *appsv1.Deployment) (*appsv1.Deployment, error) {
	existing, err := sh.client.AppsV1().Deployments(d.Namespace).Get(ctx, d.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return sh.client.AppsV1().Deployments(d.Namespace).Create(ctx, d, metav1.CreateOptions{})
	}
	if err != nil {
		return nil, err
	}
	existing.Labels = d.Labels
	existing.OwnerReferences = d.OwnerReferences
	existing.Spec = d.Spec
	return sh.client.AppsV1().Deployments(d.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
}

func (sh *Shim) upsertReplicaSet(ctx context.Context, rs *appsv1.ReplicaSet) (*appsv1.ReplicaSet, error) {
	existing, err := sh.client.AppsV1().ReplicaSets(rs.Namespace).Get(ctx, rs.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return sh.client.AppsV1().ReplicaSets(rs.Namespace).Create(ctx, rs, metav1.CreateOptions{})
	}
	if err != nil {
		return nil, err
	}
	existing.Labels = rs.Labels
	existing.OwnerReferences = rs.OwnerReferences
	existing.Spec = rs.Spec
	return sh.client.AppsV1().ReplicaSets(rs.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
}

func (sh *Shim) upsertDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) (*appsv1.DaemonSet, error) {
	existing, err := sh.client.AppsV1().DaemonSets(ds.Namespace).Get(ctx, ds.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return sh.client.AppsV1().DaemonSets(ds.Namespace).Create(ctx, ds, metav1.CreateOptions{})
	}
	if err != nil {
		return nil, err
	}
	existing.Labels = ds.Labels
	existing.OwnerReferences = ds.OwnerReferences
	existing.Spec = ds.Spec
	return sh.client.AppsV1().DaemonSets(ds.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
}

// recordUID notes the UID the apiserver assigned an object, keyed "Kind/name".
func (sh *Shim) recordUID(kindName string, uid types.UID) {
	if sh.objectUIDs == nil {
		sh.objectUIDs = map[string]types.UID{}
	}
	sh.objectUIDs[kindName] = uid
}
