// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package certificates

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newFakeClient(objs ...client.Object) client.Client {
	s := runtime.NewScheme()
	_ = admissionregistrationv1.AddToScheme(s)

	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
}

func getWebhook(t *testing.T, c client.Client, name string) *admissionregistrationv1.MutatingWebhookConfiguration {
	t.Helper()

	obj := &admissionregistrationv1.MutatingWebhookConfiguration{}
	assert.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: name}, obj))

	return obj
}

func baseOpts() WebhookReconcileOptions {
	return WebhookReconcileOptions{
		Name:      "oidc-apps-controller",
		Namespace: "garden",
		Port:      10250,
		Labels:    map[string]string{"app.kubernetes.io/name": "oidc-apps-extension"},
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "victoria-logs"},
		},
	}
}

func TestReconcileWebhookCreatesWithSelectorAndRules(t *testing.T) {
	c := newFakeClient()
	opts := baseOpts()

	assert.NoError(t, ReconcileWebhookConfiguration(context.Background(), c, opts))

	obj := getWebhook(t, c, opts.Name)

	assert.Len(t, obj.Webhooks, 2)
	assert.Equal(t, opts.Name+podsWebhookSuffix, obj.Webhooks[0].Name)
	assert.Equal(t, opts.Name+vpasWebhookSuffix, obj.Webhooks[1].Name)

	for _, w := range obj.Webhooks {
		assert.Equal(t, opts.ObjectSelector, w.ObjectSelector)
		assert.Nil(t, w.ClientConfig.CABundle, "caBundle must not be set by the reconciler")
	}

	// pods webhook rule
	assert.Equal(t, []string{""}, obj.Webhooks[0].Rules[0].APIGroups)
	assert.Equal(t, []string{"pods"}, obj.Webhooks[0].Rules[0].Resources)
	// vpas webhook rule
	assert.Equal(t, []string{"autoscaling.k8s.io"}, obj.Webhooks[1].Rules[0].APIGroups)
	assert.Equal(t, []string{"verticalpodautoscalers"}, obj.Webhooks[1].Rules[0].Resources)

	// runtime mode must not carry the cert-manager.io inject annotation
	assert.NotContains(t, obj.Annotations, certManagerInjectAnnotation)
}

func TestReconcileWebhookUpdatesSelectorPreservingCABundle(t *testing.T) {
	// Seed a webhook that already carries a caBundle (as the runtime cert manager would have injected)
	// and a stale objectSelector.
	existing := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-apps-controller"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name: "oidc-apps-controller" + podsWebhookSuffix,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte("PODS-CA"),
				},
				ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "stale"}},
			},
			{
				Name: "oidc-apps-controller" + vpasWebhookSuffix,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte("VPAS-CA"),
				},
				ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "stale"}},
			},
		},
	}

	c := newFakeClient(existing)
	opts := baseOpts()

	assert.NoError(t, ReconcileWebhookConfiguration(context.Background(), c, opts))

	obj := getWebhook(t, c, opts.Name)

	assert.Equal(t, opts.ObjectSelector, obj.Webhooks[0].ObjectSelector, "selector must be updated")
	assert.Equal(t, opts.ObjectSelector, obj.Webhooks[1].ObjectSelector, "selector must be updated")
	assert.Equal(t, []byte("PODS-CA"), obj.Webhooks[0].ClientConfig.CABundle, "caBundle must be preserved")
	assert.Equal(t, []byte("VPAS-CA"), obj.Webhooks[1].ClientConfig.CABundle, "caBundle must be preserved")
}

func TestReconcileWebhookExternalCertManagerSetsInjectAnnotation(t *testing.T) {
	c := newFakeClient()
	opts := baseOpts()
	opts.UseExternalCertManager = true

	assert.NoError(t, ReconcileWebhookConfiguration(context.Background(), c, opts))

	obj := getWebhook(t, c, opts.Name)

	assert.Equal(t, opts.Namespace+"/"+opts.Name, obj.Annotations[certManagerInjectAnnotation])
	for _, w := range obj.Webhooks {
		assert.Nil(t, w.ClientConfig.CABundle, "caBundle must be left empty for cert-manager.io to fill")
	}
}
