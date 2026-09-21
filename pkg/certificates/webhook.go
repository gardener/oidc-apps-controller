// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package certificates

import (
	"context"
	"fmt"
	"maps"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/oidc-apps-controller/pkg/constants"
)

// certManagerInjectAnnotation is the annotation cert-manager.io watches to inject the caBundle
// into the webhook clientConfig. Its value is "<namespace>/<certificate-name>".
const certManagerInjectAnnotation = "cert-manager.io/inject-ca-from"

// WebhookReconcileOptions parameterize the desired state of the controller's
// MutatingWebhookConfiguration.
type WebhookReconcileOptions struct {
	// Name is the MutatingWebhookConfiguration name and the backing Service name.
	Name string
	// Namespace is the namespace of the backing Service.
	Namespace string
	// Port is the backing Service port.
	Port int32
	// Labels are applied to the MutatingWebhookConfiguration metadata.
	Labels map[string]string
	// ObjectSelector, when set, scopes both the pods and vpas webhooks to matching objects.
	ObjectSelector *metav1.LabelSelector
	// NamespaceSelector, when set, scopes both the pods and vpas webhooks to matching namespaces.
	NamespaceSelector *metav1.LabelSelector
	// UseExternalCertManager selects the caBundle strategy. When true, the caBundle is left empty
	// and the cert-manager.io inject annotation is set so cert-manager.io fills it. When false, the
	// caBundle is owned by the runtime cert manager (see manager.go) and preserved on updates.
	UseExternalCertManager bool
}

// desiredWebhookConfiguration builds the two-webhook (pods + vpas) MutatingWebhookConfiguration
// matching the shape formerly rendered by charts/.../templates/webhook.yaml.
// It never sets caBundle; caBundle ownership is handled separately per cert mode.
func desiredWebhookConfiguration(opts WebhookReconcileOptions) *admissionregistrationv1.MutatingWebhookConfiguration {
	sideEffects := admissionregistrationv1.SideEffectClassNoneOnDryRun
	reinvocation := admissionregistrationv1.IfNeededReinvocationPolicy

	clientConfig := func(path string) admissionregistrationv1.WebhookClientConfig {
		return admissionregistrationv1.WebhookClientConfig{
			Service: &admissionregistrationv1.ServiceReference{
				Name:      opts.Name,
				Namespace: opts.Namespace,
				Path:      new(path),
				Port:      new(opts.Port),
			},
		}
	}

	rule := func(apiGroups []string, apiVersions, resources []string) admissionregistrationv1.RuleWithOperations {
		return admissionregistrationv1.RuleWithOperations{
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
				admissionregistrationv1.Update,
			},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   apiGroups,
				APIVersions: apiVersions,
				Resources:   resources,
			},
		}
	}

	webhook := func(nameSuffix, path string, rules []admissionregistrationv1.RuleWithOperations) admissionregistrationv1.MutatingWebhook {
		return admissionregistrationv1.MutatingWebhook{
			Name:                    opts.Name + nameSuffix,
			ClientConfig:            clientConfig(path),
			Rules:                   rules,
			ObjectSelector:          opts.ObjectSelector,
			NamespaceSelector:       opts.NamespaceSelector,
			SideEffects:             &sideEffects,
			AdmissionReviewVersions: []string{"v1"},
			ReinvocationPolicy:      &reinvocation,
		}
	}

	annotations := map[string]string{}
	if opts.UseExternalCertManager {
		annotations[certManagerInjectAnnotation] = opts.Namespace + "/" + opts.Name
	}

	return &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:        opts.Name,
			Labels:      opts.Labels,
			Annotations: annotations,
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			webhook(podsWebhookSuffix, constants.PodWebHookPath,
				[]admissionregistrationv1.RuleWithOperations{
					rule([]string{""}, []string{"v1"}, []string{"pods"}),
				}),
			webhook(vpasWebhookSuffix, constants.VpaWebHookPath,
				[]admissionregistrationv1.RuleWithOperations{
					rule([]string{"autoscaling.k8s.io"}, []string{"v1"}, []string{"verticalpodautoscalers"}),
				}),
		},
	}
}

// caBundleMutator, when non-nil, computes the caBundle for a managed webhook from the value
// currently on the object. It runs inside the same CreateOrUpdate call as the shape reconcile, so
// selectors/rules and caBundle are converged in a single round-trip. nil means preserve the
// existing caBundle untouched (external cert-manager.io mode, where cert-manager.io owns it).
type caBundleMutator func(webhookName string, existing []byte) ([]byte, error)

// ReconcileWebhookConfiguration creates or updates the controller's MutatingWebhookConfiguration.
// It owns metadata, selectors, rules and clientConfig. The caBundle on each webhook is either
// preserved (caMut nil) or set by caMut (runtime cert manager mode), never clobbered blindly.
func ReconcileWebhookConfiguration(ctx context.Context, c client.Client, opts WebhookReconcileOptions, caMut caBundleMutator) error {
	obj := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: opts.Name},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, c, obj, func() error {
		// Capture caBundles already present in the object, keyed by webhook name, so an update
		// does not wipe them. On create the map is empty and caBundle stays nil (to be filled later).
		existingCABundles := map[string][]byte{}
		for _, w := range obj.Webhooks {
			existingCABundles[w.Name] = w.ClientConfig.CABundle
		}

		desired := desiredWebhookConfiguration(opts)

		if obj.Labels == nil {
			obj.Labels = map[string]string{}
		}

		maps.Copy(obj.Labels, desired.Labels)

		if obj.Annotations == nil {
			obj.Annotations = map[string]string{}
		}

		maps.Copy(obj.Annotations, desired.Annotations)

		for i := range desired.Webhooks {
			name := desired.Webhooks[i].Name
			ca := existingCABundles[name]

			if caMut != nil {
				b, err := caMut(name, ca)
				if err != nil {
					return err
				}

				ca = b
			}

			desired.Webhooks[i].ClientConfig.CABundle = ca
		}

		obj.Webhooks = desired.Webhooks

		return fmt.Errorf("webhook object to reconcile:\n %s", obj.String())
	})
	if err != nil {
		return fmt.Errorf("failed to reconcile webhook configuration %q: %w", opts.Name, err)
	}

	return nil
}

// webhookReconciler is a controller-runtime Runnable that periodically reconciles the controller's
// MutatingWebhookConfiguration when the caBundle is managed externally by cert-manager.io. It owns
// the selectors/rules and the inject annotation, but never touches the caBundle.
type webhookReconciler struct {
	client client.Client
	opts   WebhookReconcileOptions
}

var (
	_ manager.Runnable               = &webhookReconciler{}
	_ manager.LeaderElectionRunnable = &webhookReconciler{}
)

// NewWebhookReconciler returns a Runnable that owns the webhook object in cert-manager.io mode.
func NewWebhookReconciler(c client.Client, opts WebhookReconcileOptions) manager.Runnable {
	return &webhookReconciler{client: c, opts: opts}
}

func (*webhookReconciler) NeedLeaderElection() bool {
	return false
}

func (w *webhookReconciler) Start(ctx context.Context) error {
	log := logf.Log.WithName("webhook-reconciler")

	if err := ReconcileWebhookConfiguration(ctx, w.client, w.opts, nil); err != nil {
		log.Error(err, "Error during initial reconcilation of webhook configuration")

		return err
	}

	ticker := time.NewTicker(syncTicker)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := ReconcileWebhookConfiguration(ctx, w.client, w.opts, nil); err != nil {
				log.Error(err, "Error reconciling webhook configuration")
			}
		case <-ctx.Done():
			log.Info("Shutting down the webhook reconciler")

			return nil
		}
	}
}
