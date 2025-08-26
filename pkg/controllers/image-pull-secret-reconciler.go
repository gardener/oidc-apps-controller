// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/oidc-apps-controller/pkg/constants"
)

const (
	// DOCKERCONFIGJSON is a standard field name in the authentication secrets for private container registries
	DOCKERCONFIGJSON = ".dockerconfigjson"
)

// ImagePullSecretReconciler holds configuration for the reconciler
type ImagePullSecretReconciler struct {
	Client     client.Client
	SecretName string
}

// Reconcile propagates the private registry secrets through the namespaces
func (r *ImagePullSecretReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	_log := log.FromContext(ctx)

	secret := &corev1.Secret{}
	if err := r.Client.Get(ctx, request.NamespacedName, secret); client.IgnoreNotFound(err) != nil {
		return reconcile.Result{}, err
	}

	if secret.GetName() != r.SecretName {
		return reconcile.Result{}, nil
	}

	secretsList := &corev1.SecretList{}
	if err := r.Client.List(ctx, secretsList,
		client.MatchingLabelsSelector{
			Selector: labels.SelectorFromSet(
				map[string]string{
					constants.LabelKey:       constants.LabelValue,
					constants.SecretLabelKey: constants.RegistrySecretLabelValue,
				},
			),
		},
	); err != nil {
		_log.Error(err, "Error fetching image pull secrets")

		return reconcile.Result{}, err
	}

	for _, imagePullSecret := range secretsList.Items {
		imagePullSecret.StringData = map[string]string{
			DOCKERCONFIGJSON: secret.StringData[DOCKERCONFIGJSON],
		}

		if err := r.Client.Update(ctx, secret); err != nil {
			_log.Error(err, "Cannot update secret",
				"name", secret.GetName(),
				"namespace", secret.GetNamespace(),
			)
		}

		_log.V(9).Info("Updated", "name", secret.GetName(), "namespace", secret.GetNamespace())
	}

	return reconcile.Result{}, nil
}
