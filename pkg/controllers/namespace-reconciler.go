// Copyright 2024 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"context"

	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/constants"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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
			Labels:    map[string]string{oidc_apps_controller.LabelKey: IMAGEPULLSECRET},
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
