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
	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/constants"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// DeploymentReconciler holds configuration for the reconciler
type DeploymentReconciler struct {
	Client client.Client
}

// Reconcile creates the auth & zutz secrets mounted to the target deployment
func (d *DeploymentReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {

	_log := log.FromContext(ctx)

	reconciledDeployment := &appsv1.Deployment{}
	if err := d.Client.Get(ctx, request.NamespacedName, reconciledDeployment); client.IgnoreNotFound(err) != nil {
		return reconcile.Result{}, err
	}

	// Skip resource without an identity
	if reconciledDeployment.GetName() == "" && reconciledDeployment.GetNamespace() == "" {
		_log.V(9).Info("reconciled deployment is empty, returning ...")
		return reconcile.Result{}, nil
	}
	_log = _log.WithValues(
		"resourceVersion", reconciledDeployment.GetResourceVersion(),
		"generation", reconciledDeployment.GetGeneration(),
	)
	_log.V(9).Info("handling deployment reconcile request")

	if reconciledDeployment.GetLabels() != nil {
		if !configuration.GetOIDCAppsControllerConfig().Match(reconciledDeployment) {
			_log.V(9).Info("reconciled deployment is not an oidc-application-controller target, returning ...")
			return reconcile.Result{}, nil
		}
	}

	// In case the deployment is an OIDC target but has not been modified by the oidc admission controller
	// then we trigger an update of the resource
	annotations := reconciledDeployment.GetAnnotations()
	if len(annotations) == 0 {
		_log.Info("Reconciled deployment is not annotated with the oidc-application-controller annotations, " +
			"re-triggering the admission controller...")
		return reconcile.Result{}, triggerGenerationIncrease(ctx, d.Client, reconciledDeployment)
	}
	if _, found := annotations[oidc_apps_controller.AnnotationTargetKey]; !found {
		_log.Info("Reconciled deployment is not annotated with the oidc-application-controller annotations, " +
			"re-triggering the admission controller...")
		return reconcile.Result{}, triggerGenerationIncrease(ctx, d.Client, reconciledDeployment)
	}

	// add a finalizer
	if !controllerutil.ContainsFinalizer(reconciledDeployment, oidc_apps_controller.Finalizer) && !reconciledDeployment.
		GetDeletionTimestamp().IsZero() {
		controllerutil.AddFinalizer(reconciledDeployment, oidc_apps_controller.Finalizer)
		if err := d.Client.Update(ctx, reconciledDeployment); err != nil {
			return reconcile.Result{}, err
		}
	}

	// Check for deletion & handle cleanup of the dependencies
	if !reconciledDeployment.GetDeletionTimestamp().IsZero() {
		_log.V(9).Info("Remove owned resources")
		if err := deleteOwnedResources(ctx, d.Client, reconciledDeployment); err != nil {
			return reconcile.Result{}, err
		}
		_log.V(9).Info("Remove finalizer")

		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := d.Client.Get(ctx, request.NamespacedName, reconciledDeployment); client.IgnoreNotFound(
				err) != nil {
				return err
			}
			controllerutil.RemoveFinalizer(reconciledDeployment, oidc_apps_controller.Finalizer)
			return d.Client.Update(ctx, reconciledDeployment)
		}); err != nil {
			_log.Error(err, "Error removing finalizer")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, nil
	}

	if err := reconcileDeploymentDependencies(ctx, d.Client, reconciledDeployment); err != nil {
		return reconcile.Result{}, err
	}

	if _log.GetV() == 9 {
		logOwnedResources(ctx, d.Client, reconciledDeployment)
	}

	return reconcile.Result{}, nil

}
