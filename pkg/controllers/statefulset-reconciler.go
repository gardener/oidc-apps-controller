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

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/constants"
)

// StatefulSetReconciler holds configuration for the reconciler
type StatefulSetReconciler struct {
	Client client.Client
}

// Reconcile creates the auth & zutz secrets mounted to the target statefulset
func (s *StatefulSetReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {

	_log := log.FromContext(ctx)

	reconciledStatefulSet := &appsv1.StatefulSet{}
	if err := s.Client.Get(ctx, request.NamespacedName, reconciledStatefulSet); client.IgnoreNotFound(err) != nil {
		return reconcile.Result{}, err
	}

	// Skip resource without an identity
	if reconciledStatefulSet.GetName() == "" && reconciledStatefulSet.GetNamespace() == "" {
		_log.V(9).Info("Reconciled statefulset is empty, returning ...")
		return reconcile.Result{}, nil
	}
	_log = _log.WithValues(
		"resourceVersion", reconciledStatefulSet.GetResourceVersion(),
		"generation", reconciledStatefulSet.GetGeneration(),
	)
	_log.V(9).Info("handling statefulset reconcile request")

	if reconciledStatefulSet.GetLabels() != nil {
		if !configuration.GetOIDCAppsControllerConfig().Match(reconciledStatefulSet) {
			_log.V(9).Info("Reconciled statefulset is not an oidc-application-controller target, returning ...")
			return reconcile.Result{}, nil
		}
	}

	// In case the deployment is an OIDC target but has not been modified by the oidc admission controller
	// then we trigger an update of the resource
	annotations := reconciledStatefulSet.GetAnnotations()
	if len(annotations) == 0 {
		_log.Info("Reconciled statefulset is not annotated with the oidc-application-controller annotations, " +
			"re-triggering the admission controller...")
		return reconcile.Result{}, triggerGenerationIncrease(ctx, s.Client, reconciledStatefulSet)
	}
	if _, found := annotations[oidc_apps_controller.AnnotationTargetKey]; !found {
		_log.Info("Reconciled statefulset is not annotated with the oidc-application-controller annotations, " +
			"re-triggering the admission controller...")
		return reconcile.Result{}, triggerGenerationIncrease(ctx, s.Client, reconciledStatefulSet)
	}

	// add a finalizer
	if !controllerutil.ContainsFinalizer(reconciledStatefulSet, oidc_apps_controller.Finalizer) && !reconciledStatefulSet.
		GetDeletionTimestamp().IsZero() {
		controllerutil.AddFinalizer(reconciledStatefulSet, oidc_apps_controller.Finalizer)
		if err := s.Client.Update(ctx, reconciledStatefulSet); err != nil {
			return reconcile.Result{}, err
		}
	}

	// Check for deletion & handle cleanup of the dependencies
	if !reconciledStatefulSet.GetDeletionTimestamp().IsZero() {
		_log.V(9).Info("Remove owned resources")
		if err := deleteOwnedResources(ctx, s.Client, reconciledStatefulSet); err != nil {
			return reconcile.Result{}, err
		}
		_log.V(9).Info("Remove finalizer")

		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := s.Client.Get(ctx, request.NamespacedName, reconciledStatefulSet); client.IgnoreNotFound(
				err) != nil {
				return err
			}
			controllerutil.RemoveFinalizer(reconciledStatefulSet, oidc_apps_controller.Finalizer)
			return s.Client.Update(ctx, reconciledStatefulSet)
		}); err != nil {
			_log.Error(err, "Error removing finalizer")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, nil
	}

	if err := reconcileStatefulSetDependencies(ctx, s.Client, reconciledStatefulSet); err != nil {
		return reconcile.Result{}, err
	}

	if _log.GetV() == 9 {
		logOwnedResources(ctx, s.Client, reconciledStatefulSet)
	}
	return reconcile.Result{}, nil

}
