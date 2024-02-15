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

	"github.com/gardener/oidc-apps-controller/pkg/configuration"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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

	return reconcile.Result{}, nil

}
