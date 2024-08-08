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

package e2e

import (
	"fmt"
	"strings"
	"time"

	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/rand"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Oidc Apps Deployment Target Test", Ordered, func() {

	Context("when a deployment is a target", Ordered, func() {

		var (
			deployment *appsv1.Deployment
			replicaSet *appsv1.ReplicaSet
			pod        *corev1.Pod
			suffix     string
		)

		// We need to implement a retryable operations in the BeforeAll block because the webhook server might not be
		// initialized before the pod is created and the admission webhook is called. In the latter case, the pod creation
		// will fail because the webhook server is not ready to serve the k8s-apiserver request.
		BeforeAll(func(ctx SpecContext) {
			// Create a deployment and the downstream replicaset and the pod as there is no controller to create them
			deployment = createTargetDeployment()
			Eventually(func() error {
				return clt.Create(ctx, deployment)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			replicaSet = createReplicaSet(deployment)
			Eventually(func() error {
				return clt.Create(ctx, replicaSet)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			pod = createPod(replicaSet)
			Eventually(func() error {
				return clt.Create(ctx, pod)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			suffix = rand.GenerateSha256(strings.Join([]string{TARGET, DEFAULT_NAMESPACE}, "-"))
		}, NodeTimeout(5*time.Second))

		AfterAll(func(ctx SpecContext) {
			Expect(client.IgnoreNotFound(clt.Delete(ctx, deployment))).Should(Succeed())
			Expect(client.IgnoreNotFound(clt.Delete(ctx, replicaSet))).Should(Succeed())
			Expect(client.IgnoreNotFound(clt.Delete(ctx, pod))).Should(Succeed())
			suffix = ""
		}, NodeTimeout(5*time.Second))

		It("there shall be auth & authz sidecar containers present in the deployment pod", func() {

			pod := &corev1.Pod{}
			Expect(clt.Get(ctx,
				client.ObjectKey{
					Namespace: DEFAULT_NAMESPACE,
					Name:      NGINX_POD,
				},
				pod)).Should(Succeed())

			Expect(pod.Spec.Containers).Should(HaveLen(3))

		})

		It("there shall be an oidc-apps annotated ingress present in the deployment namespace", func(ctx SpecContext) {
			ingresses := networkingv1.IngressList{}
			Eventually(func() error {
				if err = clt.List(ctx, &ingresses,
					client.InNamespace(DEFAULT_NAMESPACE),
					client.MatchingLabelsSelector{
						Selector: labels.SelectorFromSet(map[string]string{
							constants.LabelKey: constants.LabelValue,
						}),
					}); err != nil {
					return err
				}
				if len(ingresses.Items) == 0 {
					return fmt.Errorf("no oidc-apps ingresses are found")
				}
				for _, ingress := range ingresses.Items {
					if ingress.Name != constants.IngressName+"-"+suffix {
						continue
					}
					annotation, found := ingress.Annotations["nginx.ingress.kubernetes.io/rewrite-target"]
					if !found || annotation != "/" {
						return fmt.Errorf("An expected annotation in oidc-apps ingress: %s is not found",
							constants.IngressName+"-"+suffix)
					}
					return nil
				}
				return fmt.Errorf("An expected oidc-apps ingress: %s is not found", constants.IngressName+"-"+suffix)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())
		}, NodeTimeout(5*time.Second))

		It("there shall be an oauth2 service present in the deployment namespace", func(ctx SpecContext) {

			services := corev1.ServiceList{}
			Eventually(func() error {
				if err = clt.List(ctx, &services,
					client.InNamespace(DEFAULT_NAMESPACE),
					client.MatchingLabelsSelector{
						Selector: labels.SelectorFromSet(map[string]string{
							constants.LabelKey: constants.LabelValue,
						}),
					}); err != nil {
					return err
				}
				for _, service := range services.Items {
					if service.Name == constants.ServiceNameOauth2Service+"-"+suffix {
						return nil
					}
				}
				return fmt.Errorf("An expected oidc-apps service: %s is not found",
					constants.ServiceNameOauth2Service+"-"+suffix)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())
		}, NodeTimeout(5*time.Second))

		It("there shall be an oauth2 secret present in the deployment namespace", func(ctx SpecContext) {

			secrets := corev1.SecretList{}
			Eventually(func() error {
				if err = clt.List(ctx, &secrets,
					client.InNamespace(DEFAULT_NAMESPACE),
					client.MatchingLabelsSelector{
						Selector: labels.SelectorFromSet(map[string]string{
							constants.SecretLabelKey: constants.Oauth2LabelValue,
						}),
					}); err != nil {
					return err
				}
				if len(secrets.Items) == 0 {
					return fmt.Errorf("no oidc-apps secrets are found")
				}
				for _, secret := range secrets.Items {
					if secret.Name == constants.SecretNameOauth2Proxy+"-"+suffix {
						return nil
					}
				}
				return fmt.Errorf("An expected oidc-apps oauth2 secret: %s is not found",
					constants.SecretNameOauth2Proxy+"-"+suffix)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())
		}, NodeTimeout(5*time.Second))

		It("there shall be a rbac secret present in the deployment namespace", func(ctx SpecContext) {

			secrets := corev1.SecretList{}
			Eventually(func() error {
				if err = clt.List(ctx, &secrets,
					client.InNamespace(DEFAULT_NAMESPACE),
					client.MatchingLabelsSelector{
						Selector: labels.SelectorFromSet(map[string]string{
							constants.SecretLabelKey: constants.RbacLabelValue,
						}),
					}); err != nil {
					return err
				}
				if len(secrets.Items) == 0 {
					return fmt.Errorf("no oidc-apps secrets are found")
				}
				for _, secret := range secrets.Items {
					if secret.Name == constants.SecretNameResourceAttributes+"-"+suffix {
						return nil
					}
				}
				return fmt.Errorf("An expected oidc-apps ressource-attributes secret: %s is not found",
					constants.SecretNameResourceAttributes+"-"+suffix)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())
		}, NodeTimeout(5*time.Second))
	}) // End of Context("when a deployment is a target")

	Context("when a deployment is not a target", func() {
		var (
			deployment *appsv1.Deployment
			replicaSet *appsv1.ReplicaSet
			pod        *corev1.Pod
			suffix     string
		)

		// We need to implement a retryable operations in the BeforeAll block because the webhook server might not be
		// initialized before the pod is created and the admission webhook is called. In the latter case, the pod creation
		// will fail because the webhook server is not ready to serve the k8s-apiserver request.
		BeforeAll(func(ctx SpecContext) {
			// Create a deployment and the downstream replicaset and the pod as there is no controller to create them
			deployment = createNonTargetDeployment()
			Eventually(func() error {
				return clt.Create(ctx, deployment)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			replicaSet = createReplicaSet(deployment)
			Eventually(func() error {
				return clt.Create(ctx, replicaSet)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			pod = createPod(replicaSet)
			Eventually(func() error {
				return clt.Create(ctx, pod)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())
			suffix = rand.GenerateSha256(strings.Join([]string{NON_TARGET, DEFAULT_NAMESPACE}, "-"))
		}, NodeTimeout(5*time.Second))

		AfterAll(func(ctx SpecContext) {
			Expect(client.IgnoreNotFound(clt.Delete(ctx, deployment))).Should(Succeed())
			Expect(client.IgnoreNotFound(clt.Delete(ctx, replicaSet))).Should(Succeed())
			Expect(client.IgnoreNotFound(clt.Delete(ctx, pod))).Should(Succeed())
		}, NodeTimeout(5*time.Second))

		It("there shall be no auth & authz proxies present in the deployment pod", func() {

			pod := &corev1.Pod{}
			Expect(clt.Get(ctx,
				client.ObjectKey{
					Namespace: DEFAULT_NAMESPACE,
					Name:      NGINX_POD,
				},
				pod)).Should(Succeed())
			Expect(pod.Spec.Containers).Should(HaveLen(1))

		})

		It("there shall be no oidc-apps ingress present in the deployment namespace", func() {

			ingress := &networkingv1.Ingress{}
			err = clt.Get(ctx,
				client.ObjectKey{
					Namespace: DEFAULT_NAMESPACE,
					Name:      constants.IngressName + "-" + suffix,
				}, ingress)
			Expect(err).Should(HaveOccurred())
			Expect(errors.IsNotFound(err)).Should(BeTrue())
		})

		It("there shall be no oauth2 service present in the deployment namespace", func() {
			service := &corev1.Service{}
			err := clt.Get(ctx,
				client.ObjectKey{
					Namespace: DEFAULT_NAMESPACE,
					Name:      constants.ServiceNameOauth2Service + "-" + suffix,
				}, service)
			Expect(err).Should(HaveOccurred())
			Expect(errors.IsNotFound(err)).Should(BeTrue())

		})

		It("there shall be no oauth2 secret present in the deployment namespace", func() {
			secret := &corev1.Secret{}
			err := clt.Get(ctx,
				client.ObjectKey{
					Namespace: DEFAULT_NAMESPACE,
					Name:      constants.SecretNameOauth2Proxy + "-" + suffix,
				}, secret)
			Expect(err).Should(HaveOccurred())
			Expect(errors.IsNotFound(err)).Should(BeTrue())
		})

		It("there shall be no rbac secret present in the deployment namespace", func() {
			secret := &corev1.Secret{}
			err := clt.Get(ctx,
				client.ObjectKey{
					Namespace: DEFAULT_NAMESPACE,
					Name:      constants.SecretNameResourceAttributes + "-" + suffix,
				}, secret)
			Expect(err).Should(HaveOccurred())
			Expect(errors.IsNotFound(err)).Should(BeTrue())
		})
	}) // End of Context("when a deployment is not a target")
})
