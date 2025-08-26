// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/oidc-apps-controller/pkg/constants"
)

// NamespaceReconciler holds configuration for the reconciler
type NamespaceReconciler struct {
	Client client.Client
	Secret types.NamespacedName
}

// Reconcile propagates private docker registry secrets on cluster namespaces
func (n *NamespaceReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	_log := log.FromContext(ctx)

	// Get the namespace object
	ns := &corev1.Namespace{}
	if err := n.Client.Get(ctx, request.NamespacedName, ns); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	// Skip if the namespace is being deleted
	if ns.GetDeletionTimestamp() != nil {
		return reconcile.Result{}, nil
	}

	// Get the original secret
	originalSecret := &corev1.Secret{}
	if err := n.Client.Get(ctx, n.Secret, originalSecret); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	// Create a copy of the secret in the new namespace
	secretCopy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      originalSecret.Name,
			Namespace: request.Name,
			Labels: map[string]string{
				constants.LabelKey:       constants.LabelValue,
				constants.SecretLabelKey: constants.RegistrySecretLabelValue,
			},
		},
		Data: originalSecret.Data,
		Type: originalSecret.Type,
	}

	// Check if the secret already exists in the new namespace
	if err := n.Client.Get(ctx, client.ObjectKeyFromObject(secretCopy), &corev1.Secret{}); err != nil {
		if !errors.IsNotFound(err) {
			return reconcile.Result{}, err
		}

		// Secret does not exist, create it
		if err := n.Client.Create(ctx, secretCopy); err != nil {
			_log.Info("Created private registry secret")

			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}
