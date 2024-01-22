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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardenextensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/constants"
)

func fetchOidcAppsServices(ctx context.Context, c client.Client, object client.Object) (*corev1.ServiceList,
	error) {
	oidcService := &corev1.ServiceList{}
	oidcLabelSelector, _ := labels.Parse(oidc_apps_controller.LabelKey)

	if err := c.List(ctx, oidcService,
		client.InNamespace(object.GetNamespace()),
		client.MatchingLabelsSelector{
			Selector: oidcLabelSelector,
		},
	); err != nil {
		return oidcService, client.IgnoreNotFound(err)
	}

	ownedServices := make([]corev1.Service, 0, len(oidcService.Items))
	for _, service := range oidcService.Items {
		if isAnOwnedResource(object, &service) {
			ownedServices = append(ownedServices, service)
		}
	}

	return &corev1.ServiceList{Items: ownedServices}, nil
}

func fetchOidcAppsIngress(ctx context.Context, c client.Client, object client.Object) (*networkingv1.IngressList,
	error) {
	oidcIngress := &networkingv1.IngressList{}
	oidcLabelSelector, _ := labels.Parse(oidc_apps_controller.LabelKey)

	if err := c.List(ctx, oidcIngress,
		client.InNamespace(object.GetNamespace()),
		client.MatchingLabelsSelector{
			Selector: oidcLabelSelector,
		},
	); err != nil {
		return oidcIngress, client.IgnoreNotFound(err)
	}

	ownedIngresses := make([]networkingv1.Ingress, 0, len(oidcIngress.Items))
	for _, ingress := range oidcIngress.Items {
		if isAnOwnedResource(object, &ingress) {
			ownedIngresses = append(ownedIngresses, ingress)
		}
	}
	return &networkingv1.IngressList{Items: ownedIngresses}, nil
}

func fetchOidcAppsSecrets(ctx context.Context, c client.Client, object client.Object) (*corev1.SecretList,
	error) {
	oidcSecrets := &corev1.SecretList{}
	oidcLabelSelector, _ := labels.Parse(oidc_apps_controller.LabelKey)

	if err := c.List(ctx, oidcSecrets,
		client.InNamespace(object.GetNamespace()),
		client.MatchingLabelsSelector{
			Selector: oidcLabelSelector,
		},
	); err != nil {
		return oidcSecrets, client.IgnoreNotFound(err)
	}

	ownedSecrets := make([]corev1.Secret, 0, len(oidcSecrets.Items))
	for _, secret := range oidcSecrets.Items {
		if isAnOwnedResource(object, &secret) {
			ownedSecrets = append(ownedSecrets, secret)
		}
	}

	return &corev1.SecretList{Items: ownedSecrets}, nil
}

func fetchResourceAttributesNamespace(ctx context.Context, c client.Client, object client.Object) string {
	_log := log.FromContext(ctx)
	// In the case when we are not running on a gardener seed cluster, just return the target namespace
	if os.Getenv(oidc_apps_controller.GARDEN_KUBECONFIG) == "" {
		return object.GetNamespace()
	}
	// In the case the target is in the garden namespace, then we shall not set a namespace.
	// The goal is the kick in only the gardener operators access which should have cluster scoped access
	if object.GetNamespace() == oidc_apps_controller.GARDEN_NAMESPACE {
		return ""
	}
	// In other cases, fetch the cluster resources and set the project namespace
	clusters := &gardenextensionsv1alpha1.ClusterList{}

	if err := c.List(ctx, clusters); err != nil {
		_log.Error(err, "Failed to list Cluster resources")
	}

	for _, cluster := range clusters.Items {
		// Cluster name differ from the target namespace
		if cluster.GetName() != object.GetNamespace() {
			continue
		}
		var shoot gardencorev1beta1.Shoot
		if err := json.Unmarshal(cluster.Spec.Shoot.Raw, &shoot); err != nil {
			_log.Error(err, "Failed to parse the shoot raw extension", "cluster", cluster.Name)
			return ""
		}
		_log.Info("Fetched resource_attribute", "namespace", shoot.GetNamespace(), "shoot", shoot.GetName())
		return shoot.GetNamespace()
	}
	return ""
}

// reconcileDeployementDependencies is the function responsible for managing authentication & authorization dependencies.
// It reconciles the needed secrets, ingresses and services.
func reconcileDeployementDependencies(ctx context.Context, c client.Client, object *v1.Deployment) error {
	_log := log.FromContext(ctx)

	// Service for the oauth2-proxy sidecar
	var oauth2Service corev1.Service

	// Ingress for the oauth2-proxy sidecar
	var oauth2Ingress networkingv1.Ingress

	// Secret with oidc configuration for oauth2-proxy sidecar
	var oauth2Secret corev1.Secret

	// Secret with resource attributes for the rbac-proxy sidecar
	var rbacSecret corev1.Secret

	// Secret with oidc CA certificate for the rbac-proxy sidecar
	var oidcCABundleSecret corev1.Secret

	// Optional secret with kubeconfig the rbac-proxy sidecar
	var kubeConfig corev1.Secret

	var (
		mutateFn = func() error { return nil }
		op       controllerutil.OperationResult
		checksum string
		err      error
	)
	if object.GetDeletionTimestamp() == nil {

		oauth2Secret, err = createOauth2Secret(object)
		if err != nil {
			return err
		}
		if err := controllerutil.SetOwnerReference(object, &oauth2Secret, c.Scheme()); err != nil {
			return err
		}
		if len(object.Spec.Template.Annotations) == 0 {
			object.Spec.Template.Annotations = make(map[string]string, 1)
		}
		if checksum, err = getHash(oauth2Secret.String()); err != nil {
			return err
		}
		object.Spec.Template.Annotations["checksum/secret-oauth2-proxy"] = checksum

		oauth2Service, err = createOauth2Service(object)
		if err != nil {
			return err
		}
		if err := controllerutil.SetOwnerReference(object, &oauth2Service, c.Scheme()); err != nil {
			return err
		}

		ns := fetchResourceAttributesNamespace(ctx, c, object)
		rbacSecret, err = createResourceAttributesSecret(object, ns)
		if err != nil {
			return err
		}
		if err := controllerutil.SetOwnerReference(object, &rbacSecret, c.Scheme()); err != nil {
			return err
		}

		// kubeconfig secret is optionally added to the kube-rbac-proxy
		kubeConfig, err = createKubeconfigSecret(object)
		if err == nil {
			if err = controllerutil.SetOwnerReference(object, &kubeConfig, c.Scheme()); err != nil {
				_log.Error(err, "Failed to set owner reference to kubeconfig secret")
			}
			op, err = controllerutil.CreateOrUpdate(ctx, c, &kubeConfig, mutateFn)
			if err != nil {
				return err
			} else {
				_log.Info(string(op))
			}
		}
		if err != nil && !errors.Is(err, errSecretDoesNotExist) {
			return err
		}
		// kube-rbac-proxy does not provide configuration for kubeconfig
		oidcCABundleSecret, err = createOidcCaBundleSecret(object)
		if err != nil {
			return err
		}
		if oidcCABundleSecret.Name != "" {
			if err = controllerutil.SetOwnerReference(object, &oidcCABundleSecret, c.Scheme()); err != nil {
				_log.Error(err, "Failed to set owner reference to oidc ca bundle secret")
			}
			op, err = controllerutil.CreateOrUpdate(ctx, c, &oidcCABundleSecret, mutateFn)
			if err != nil {
				return err
			} else {
				_log.Info(string(op))
			}
		}

		oauth2Ingress, err = createIngress(object.GetAnnotations()[oidc_apps_controller.AnnotationHostKey], object)
		if err != nil {
			return err
		}
		if err = controllerutil.SetOwnerReference(object, &oauth2Ingress,
			c.Scheme()); err != nil {
			return err
		}

		//TODO: check update operation
		op, err = controllerutil.CreateOrUpdate(ctx, c, &oauth2Secret, mutateFn)
		if err != nil {
			return err
		} else {
			_log.Info(string(op))
		}

		op, err = controllerutil.CreateOrUpdate(ctx, c, &oauth2Service, mutateFn)
		if err != nil {
			return err
		} else {
			_log.Info(string(op))
		}

		op, err = controllerutil.CreateOrUpdate(ctx, c, &rbacSecret, mutateFn)
		if err != nil {
			return err
		} else {
			_log.Info(string(op))
		}

		op, err = controllerutil.CreateOrUpdate(ctx, c, &oauth2Ingress, mutateFn)
		if err != nil {
			return err
		} else {
			_log.Info(string(op))
		}
	}

	return nil
}

func getHash(s string) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, strings.NewReader(s)); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func reconcileStatefulSetDependencies(ctx context.Context, c client.Client, object *v1.StatefulSet) error {
	_log := log.FromContext(ctx)

	// Service for the oauth2-proxy sidecar
	var oauth2Service corev1.Service

	// Ingress for the oauth2-proxy sidecar
	var oauth2Ingress networkingv1.Ingress

	// Secret with oidc configuration for oauth2-proxy sidecar
	var oauth2Secret corev1.Secret

	// Secret with resource attributes for the rbac-proxy sidecar
	var rbacSecret corev1.Secret

	// Secret with oidc CA certificate for the rbac-proxy sidecar
	var oidcCABundleSecret corev1.Secret

	// Optional secret with kubeconfig the rbac-proxy sidecar
	var kubeConfig corev1.Secret

	var (
		mutateFn = func() error { return nil }
		op       controllerutil.OperationResult
		checksum string
		err      error
	)
	if object.GetDeletionTimestamp() == nil {

		oauth2Secret, err = createOauth2Secret(object)
		if err != nil {
			return err
		}
		if err = controllerutil.SetOwnerReference(object, &oauth2Secret, c.Scheme()); err != nil {
			return err
		}
		op, err = controllerutil.CreateOrUpdate(ctx, c, &oauth2Secret, mutateFn)
		if err != nil {
			_log.Error(err, "update oauth2 secret")
			return err
		} else {
			_log.Info(string(op))
		}

		if len(object.Spec.Template.Annotations) == 0 {
			object.Spec.Template.Annotations = make(map[string]string, 1)
		}
		if checksum, err = getHash(oauth2Secret.String()); err != nil {
			return err
		}
		object.Spec.Template.Annotations["checksum/secret-oauth2-proxy"] = checksum

		// List the Pods
		podList := &corev1.PodList{}
		labelSelector := client.MatchingLabels(object.Spec.Selector.MatchLabels)
		if err := c.List(ctx, podList, labelSelector, client.InNamespace(object.GetNamespace())); err != nil {
			return err
		}
		hostPrefix := object.GetAnnotations()[oidc_apps_controller.AnnotationHostKey]
		suffix := object.GetAnnotations()[oidc_apps_controller.AnnotationSuffixKey]
		for _, pod := range podList.Items {
			if len(pod.Annotations) == 0 {
				pod.Annotations = make(map[string]string, 1)
			}
			pod.Annotations[oidc_apps_controller.AnnotationSuffixKey] = suffix

			oauth2Service, err = createOauth2Service(&pod)
			if err != nil {
				return err
			}
			if err := controllerutil.SetOwnerReference(&pod, &oauth2Service, c.Scheme()); err != nil {
				return err
			}

			op, err = controllerutil.CreateOrUpdate(ctx, c, &oauth2Service, mutateFn)
			if err != nil {
				_log.Error(err, "update oauth2 service")
				return err
			} else {
				_log.Info(string(op))
			}

			// There shall be an ingress for each statefulset pod
			host, domain, found := strings.Cut(hostPrefix, ".")
			if found {
				host = fmt.Sprintf("%s-%s.%s", pod.GetName(), pod.GetNamespace(), domain)
			}
			_log.V(9).Info("Set", "host", host)
			oauth2Ingress, err = createIngress(host, &pod)
			if err != nil {
				return err
			}
			if err := controllerutil.SetOwnerReference(&pod, &oauth2Ingress, c.Scheme()); err != nil {
				return err
			}

			op, err = controllerutil.CreateOrUpdate(ctx, c, &oauth2Ingress, mutateFn)
			if err != nil {
				_log.Error(err, "update oauth2 ingress")
				return err
			} else {
				_log.Info(string(op))
			}

		}

		ns := fetchResourceAttributesNamespace(ctx, c, object)
		rbacSecret, err = createResourceAttributesSecret(object, ns)
		if err != nil {
			return err
		}
		if err := controllerutil.SetOwnerReference(object, &rbacSecret, c.Scheme()); err != nil {
			return err
		}

		// kubeconfig secret is optionally added to the kube-rbac-proxy
		kubeConfig, err = createKubeconfigSecret(object)
		if err == nil {
			if err = controllerutil.SetOwnerReference(object, &kubeConfig, c.Scheme()); err != nil {
				_log.Error(err, "Failed to set owner reference to kubeconfig secret")
			}
			op, err = controllerutil.CreateOrUpdate(ctx, c, &kubeConfig, mutateFn)
			if err != nil {
				_log.Error(err, "update kubeconfig secret")
				return err
			} else {
				_log.Info(string(op))
			}
		}
		if err != nil && !errors.Is(err, errSecretDoesNotExist) {
			return err
		}
		// kube-rbac-proxy does not provide configuration for kubeconfig
		oidcCABundleSecret, err = createOidcCaBundleSecret(object)
		if err != nil {
			return err
		}
		if oidcCABundleSecret.Name != "" {
			if err = controllerutil.SetOwnerReference(object, &oidcCABundleSecret, c.Scheme()); err != nil {
				_log.Error(err, "Failed to set owner reference to oidc ca bundle secret")
			}
			op, err = controllerutil.CreateOrUpdate(ctx, c, &oidcCABundleSecret, mutateFn)
			if err != nil {
				_log.Error(err, "update oidcCABundleSecret secret")
				return err
			} else {
				_log.Info(string(op))
			}
		}

		op, err = controllerutil.CreateOrUpdate(ctx, c, &rbacSecret, mutateFn)
		if err != nil {
			_log.Error(err, "update rbacSecret secret")
			return err
		} else {
			_log.Info(string(op))
		}

	}

	/**/

	return nil
}

func triggerGenerationIncrease(ctx context.Context, c client.Client, object client.Object) error {
	gen := object.GetGeneration()
	object.SetGeneration(gen + 1)
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return c.Update(ctx, object)
	}); err != nil {
		log.FromContext(ctx).Error(err, "failed to increase the generation")
		return err
	}
	return nil
}
