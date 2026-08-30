package controller

import (
	"bytes"
	"context"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// WebhookCABundleReconciler keeps the join webhook's caBundle correct for as
// long as the manager runs. The startup patch alone is not enough: if the
// MutatingWebhookConfiguration is recreated or its caBundle cleared while the
// manager is running (a re-apply of the manifests, a Helm upgrade), it would
// otherwise stay empty until the next restart, and with failurePolicy:
// Ignore every join would silently no-op. This watches that one object and
// re-patches it the moment its caBundle drifts from the manager's CA.
type WebhookCABundleReconciler struct {
	client.Client
	// ConfigName is the MutatingWebhookConfiguration to keep patched.
	ConfigName string
	// CABundle is the manager's webhook-serving CA that every webhook's
	// clientConfig.caBundle must carry.
	CABundle []byte
}

func (r *WebhookCABundleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Name != r.ConfigName {
		return ctrl.Result{}, nil
	}
	var cfg admissionregistrationv1.MutatingWebhookConfiguration
	if err := r.Get(ctx, types.NamespacedName{Name: req.Name}, &cfg); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	drift := false
	for i := range cfg.Webhooks {
		if !bytes.Equal(cfg.Webhooks[i].ClientConfig.CABundle, r.CABundle) {
			cfg.Webhooks[i].ClientConfig.CABundle = r.CABundle
			drift = true
		}
	}
	if !drift {
		return ctrl.Result{}, nil
	}
	if err := r.Update(ctx, &cfg); err != nil {
		return ctrl.Result{}, err
	}
	ctrl.LoggerFrom(ctx).Info("re-patched drifted join-webhook CA bundle", "mutatingWebhookConfiguration", req.Name)
	return ctrl.Result{}, nil
}

func (r *WebhookCABundleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Only the one named MutatingWebhookConfiguration, so this never
	// touches any other admission webhook in the cluster.
	onlyOurs := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetName() == r.ConfigName
	})
	return ctrl.NewControllerManagedBy(mgr).
		For(&admissionregistrationv1.MutatingWebhookConfiguration{}, builder.WithPredicates(onlyOurs)).
		Named("webhook-ca-bundle").
		Complete(r)
}
