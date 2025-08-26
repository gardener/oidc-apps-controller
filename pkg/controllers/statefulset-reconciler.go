// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
)

// StatefulSetReconciler holds configuration for the reconciler
type StatefulSetReconciler struct {
	Client client.Client
}

// Reconcile creates the auth & zutz secrets mounted to the target statefulset
func (s *StatefulSetReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reconciledStatefulSet := &appsv1.StatefulSet{}

	if err := s.Client.Get(ctx, request.NamespacedName, reconciledStatefulSet); client.IgnoreNotFound(err) != nil {
		return reconcile.Result{}, err
	}

	_log := log.FromContext(ctx).WithValues("resourceVersion", reconciledStatefulSet.GetResourceVersion())

	if reconciledStatefulSet.GetName() == "" && reconciledStatefulSet.GetNamespace() == "" {
		_log.V(9).Info("Reconciled statefulset is empty, returning ...")

		return reconcile.Result{}, nil
	}

	_log.V(9).Info("handling statefulset reconcile request")

	if !configuration.GetOIDCAppsControllerConfig().Match(reconciledStatefulSet) {
		_log.V(9).Info("Reconciled statefulset is not an oidc-application-controller target, returning ...")

		return reconcile.Result{}, nil
	}

	if !hasOidcAppsPods(ctx, s.Client, reconciledStatefulSet) {
		return reconcile.Result{}, nil
	}

	// Check for deletion & handle cleanup of the dependencies
	if !reconciledStatefulSet.GetDeletionTimestamp().IsZero() {
		_log.V(9).Info("Remove owned resources")

		if err := deleteOwnedResources(ctx, s.Client, reconciledStatefulSet); err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	}

	if err := reconcileStatefulSetDependencies(ctx, s.Client, reconciledStatefulSet); err != nil {
		return reconcile.Result{}, err
	}

	_log.Info("reconciled statefulset successfully")

	return reconcile.Result{}, nil
}
