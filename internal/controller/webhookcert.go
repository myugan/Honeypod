package controller

import (
	"context"
	"crypto/tls"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"honeypod.io/honeypod/internal/certs"
)

// generateWebhookServingCert issues a fresh, self-signed CA + leaf server
// certificate for the admission-webhook HTTPS server, reusing
// internal/certs -- the same package that issues each Decoy's own decoy
// identity -- rather than building a second certificate system.
func generateWebhookServingCert(dnsNames []string) (leafCertPEM, leafKeyPEM, caCertPEM []byte, err error) {
	caCertPEM, caKeyPEM, err := certs.GenerateCA("kubernetes")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating webhook CA: %w", err)
	}
	leafCertPEM, leafKeyPEM, err = certs.IssueServerCert(caCertPEM, caKeyPEM, dnsNames)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("issuing webhook serving cert: %w", err)
	}
	return leafCertPEM, leafKeyPEM, caCertPEM, nil
}

// EnsureWebhookServingCert returns a stable TLS certificate for the
// admission-webhook HTTPS server, persisted in a Secret so it survives a
// manager restart -- a fresh cert on every restart would mean the real
// apiserver's own admission-webhook trust cache (which doesn't refresh
// instantly) rejects the new cert for up to a minute after every restart,
// with failurePolicy: Ignore silently skipping pod joins the whole time.
// Confirmed live: this exact race caused joins to silently no-op right
// after a manager restart. Reusing one cert across restarts removes the
// race entirely -- the caBundle never needs to change once set.
func EnsureWebhookServingCert(ctx context.Context, c client.Client, namespace, secretName string, dnsNames []string) (cert tls.Certificate, caPEM []byte, err error) {
	key := types.NamespacedName{Namespace: namespace, Name: secretName}

	loadStored := func() (tls.Certificate, []byte, error) {
		var secret corev1.Secret
		if err := c.Get(ctx, key, &secret); err != nil {
			return tls.Certificate{}, nil, err
		}
		tlsCert, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
		if err != nil {
			return tls.Certificate{}, nil, fmt.Errorf("parsing stored webhook cert: %w", err)
		}
		return tlsCert, secret.Data["ca.crt"], nil
	}

	tlsCert, storedCA, getErr := loadStored()
	if getErr == nil {
		return tlsCert, storedCA, nil
	}
	if !apierrors.IsNotFound(getErr) {
		return tls.Certificate{}, nil, fmt.Errorf("getting webhook cert secret: %w", getErr)
	}

	leafCertPEM, leafKeyPEM, caCertPEM, err := generateWebhookServingCert(dnsNames)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tlsCert, err = tls.X509KeyPair(leafCertPEM, leafKeyPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("building webhook tls.Certificate: %w", err)
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Data: map[string][]byte{
			"tls.crt": leafCertPEM,
			"tls.key": leafKeyPEM,
			"ca.crt":  caCertPEM,
		},
	}
	if err := c.Create(ctx, &secret); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return tls.Certificate{}, nil, fmt.Errorf("storing webhook cert secret: %w", err)
		}
		// Someone else won the create. Returning the cert generated here
		// would serve a keypair whose CA is not the one now stored -- and
		// the stored one is what WebhookCABundleReconciler publishes as the
		// caBundle, so the apiserver would reject every handshake. Read
		// back what actually landed and use that instead.
		return loadStored()
	}
	return tlsCert, caCertPEM, nil
}
