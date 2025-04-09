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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/rand"
)

var _ = Describe("Oidc Apps Statefulset Target Test", Ordered, func() {
	Context("when a statefulset is a target", Ordered, func() {
		var (
			statefulSet       *appsv1.StatefulSet
			pod0, pod1        *corev1.Pod
			suffix, podSuffix string
		)

		// We need to implement a retryable operations in the BeforeAll block because the webhook server might not be
		// initialized before the pod is created and the admission webhook is called. In the latter case, the pod creation
		// will fail because the webhook server is not ready to serve the k8s-apiserver request.
		BeforeAll(func(ctx SpecContext) {
			// Create a deployment and the downstream replicaset and the pod as there is no controller to create them
			statefulSet = createTargetStatefulSet()
			Eventually(func() error {
				return clt.Create(ctx, statefulSet)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			// Target StatefulSet shall be scaled with 2 replicas
			pod0 = createStatefulSetPod(statefulSet, "0")
			Eventually(func() error {
				return clt.Create(ctx, pod0)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())
			pod1 = createStatefulSetPod(statefulSet, "1")
			Eventually(func() error {
				return clt.Create(ctx, pod1)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			suffix = rand.GenerateSha256(strings.Join([]string{target, defaultNamespace}, "-"))
		}, NodeTimeout(5*time.Second))

		AfterAll(func(ctx SpecContext) {
			Expect(client.IgnoreNotFound(clt.Delete(ctx, statefulSet))).Should(Succeed())
			Expect(client.IgnoreNotFound(clt.Delete(ctx, pod0))).Should(Succeed())
			Expect(client.IgnoreNotFound(clt.Delete(ctx, pod1))).Should(Succeed())
			suffix = ""
		}, NodeTimeout(5*time.Second))

		It("there shall be auth & authz sidecar containers present in the statefulset pods", func() {
			pod := &corev1.Pod{}
			Expect(clt.Get(ctx,
				client.ObjectKey{
					Namespace: defaultNamespace,
					Name:      target + "-0",
				},
				pod)).Should(Succeed())

			Expect(pod.Spec.Containers).Should(HaveLen(3))
			pod = &corev1.Pod{}
			Expect(clt.Get(ctx,
				client.ObjectKey{
					Namespace: defaultNamespace,
					Name:      target + "-1",
				},
				pod)).Should(Succeed())

			Expect(pod.Spec.Containers).Should(HaveLen(3))
		})

		It("there shall be an oidc-apps ingress per pod present in the statefulset namespace", func(ctx SpecContext) {
			ingresses := networkingv1.IngressList{}
			By("checking the ingress for the first pod")
			Eventually(func() error {
				if err = clt.List(ctx, &ingresses,
					client.InNamespace(defaultNamespace),
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
					podSuffix = rand.GenerateSha256(target + "-0-" + defaultNamespace)
					if ingress.Name != constants.IngressName+"-0-"+podSuffix {
						continue
					}
					annotation, found := ingress.Annotations["nginx.ingress.kubernetes.io/rewrite-target"]
					if !found || annotation != "/" {
						return fmt.Errorf("An expected annotation in oidc-apps ingress: %s is not found",
							constants.IngressName+"-"+suffix)
					}

					return nil
				}

				return fmt.Errorf("An expected oidc-apps ingress: %s is not found", constants.IngressName+"-0-"+podSuffix)
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())

			By("checking the ingress for the second pod")
			Eventually(func() error {
				if err = clt.List(ctx, &ingresses,
					client.InNamespace(defaultNamespace),
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
					podSuffix = rand.GenerateSha256(target + "-1-" + defaultNamespace)
					if ingress.Name != constants.IngressName+"-1-"+podSuffix {
						continue
					}
					annotation, found := ingress.Annotations["nginx.ingress.kubernetes.io/rewrite-target"]
					if !found || annotation != "/" {
						return fmt.Errorf("An expected annotation in oidc-apps ingress: %s is not found",
							constants.IngressName+"-"+suffix)
					}

					return nil
				}

				return fmt.Errorf("An expected oidc-apps ingress: %s is not found", constants.IngressName+"-1-"+podSuffix)
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())
		})

		It("there shall be oauth2 services per pod present in the statefulset namespace", func(ctx SpecContext) {
			services := corev1.ServiceList{}
			By("checking the service for the first pod")
			Eventually(func() error {
				if err = clt.List(ctx, &services,
					client.InNamespace(defaultNamespace),
					client.MatchingLabelsSelector{
						Selector: labels.SelectorFromSet(map[string]string{
							constants.LabelKey: constants.LabelValue,
						}),
					}); err != nil {
					return err
				}
				podSuffix = rand.GenerateSha256(target + "-0-" + defaultNamespace)
				for _, service := range services.Items {
					if service.Name == constants.ServiceNameOauth2Service+"-0-"+podSuffix {
						return nil
					}
				}

				return fmt.Errorf("An expected oidc-apps service: %s is not found",
					constants.ServiceNameOauth2Service+"-0-"+podSuffix)
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())

			By("checking the service for the second pod")
			Eventually(func() error {
				if err = clt.List(ctx, &services,
					client.InNamespace(defaultNamespace),
					client.MatchingLabelsSelector{
						Selector: labels.SelectorFromSet(map[string]string{
							constants.LabelKey: constants.LabelValue,
						}),
					}); err != nil {
					return err
				}
				podSuffix = rand.GenerateSha256(target + "-1-" + defaultNamespace)
				for _, service := range services.Items {
					if service.Name == constants.ServiceNameOauth2Service+"-1-"+podSuffix {
						return nil
					}
				}

				return fmt.Errorf("An expected oidc-apps service: %s is not found",
					constants.ServiceNameOauth2Service+"-0-"+podSuffix)
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())
		})

		It("there shall be an oauth2 secret present in the statefulset namespace", func(ctx SpecContext) {
			secrets := corev1.SecretList{}
			Eventually(func() error {
				if err = clt.List(ctx, &secrets,
					client.InNamespace(defaultNamespace),
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
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())
		})

		It("there shall be a rbac secret present in the statefulset namespace", func(ctx SpecContext) {
			secrets := corev1.SecretList{}
			Eventually(func() error {
				if err = clt.List(ctx, &secrets,
					client.InNamespace(defaultNamespace),
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
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())
		})
	})
})
