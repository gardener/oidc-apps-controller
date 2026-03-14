// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/randutils"
)

var _ = Describe("Oidc Apps HTTPRoute Deployment Target Test", Ordered, func() {
	Context("when a deployment is a target with HTTPRoute enabled", Ordered, func() {
		BeforeAll(func(ctx SpecContext) {
			deployment := createHTTPRouteTargetDeployment()
			Eventually(func() error {
				return clt.Create(ctx, deployment)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			replicaSet := createReplicaSet(deployment)
			Eventually(func() error {
				return clt.Create(ctx, replicaSet)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			pod := createPod(replicaSet)
			Eventually(func() error {
				return clt.Create(ctx, pod)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())
		}, NodeTimeout(5*time.Second))

		AfterAll(func(ctx SpecContext) {
			cleanUpAllDeployments(ctx)
		}, NodeTimeout(5*time.Second))

		It("there shall be auth & authz sidecar containers present in the deployment pod", func() {
			pod := &corev1.Pod{}
			d := hash5(client.ObjectKey{Name: httpRouteTarget, Namespace: defaultNamespace})
			rs := hash5(client.ObjectKey{Name: strings.Join([]string{nginxRS, d}, "-"), Namespace: defaultNamespace})
			Expect(clt.Get(ctx,
				client.ObjectKey{
					Name:      strings.Join([]string{nginxPod, rs}, "-"),
					Namespace: defaultNamespace,
				},
				pod,
			)).To(Succeed())
			Expect(pod.Spec.Containers).Should(HaveLen(3))
		})

		It("there shall be an oidc-apps annotated HTTPRoute present in the deployment namespace", func(ctx SpecContext) {
			httpRoutes := gatewayv1.HTTPRouteList{}
			suffix := randutils.GenerateSha256(strings.Join([]string{httpRouteTarget, defaultNamespace}, "-"))
			Eventually(func() error {
				if err = clt.List(ctx, &httpRoutes,
					client.InNamespace(defaultNamespace),
					client.MatchingLabelsSelector{
						Selector: labels.SelectorFromSet(map[string]string{
							constants.LabelKey: constants.LabelValue,
						}),
					}); err != nil {
					return err
				}

				if len(httpRoutes.Items) == 0 {
					return errors.New("no oidc-apps HTTPRoutes are found")
				}

				for _, httpRoute := range httpRoutes.Items {
					if httpRoute.Name != constants.HTTPRouteName+"-"+suffix {
						continue
					}

					// Ensure configured labels are set on the HTTPRoute.
					confTarget := configuration.GetOIDCAppsControllerConfig().FetchTarget(&httpRoute)
					wantHTTPRouteLabels := map[string]string{
						constants.LabelKey: constants.LabelValue,
					}
					maps.Copy(wantHTTPRouteLabels, confTarget.Labels)

					if !maps.Equal(httpRoute.Labels, wantHTTPRouteLabels) {
						return fmt.Errorf("mismatched labels for target and HTTPRoute: %s", httpRoute.Name)
					}

					// Verify the host is set correctly
					if len(httpRoute.Spec.Hostnames) != 1 {
						return fmt.Errorf("expected 1 hostname, got %d", len(httpRoute.Spec.Hostnames))
					}

					expectedHost := httpRouteTarget + "-" + defaultNamespace + "." + domain
					if string(httpRoute.Spec.Hostnames[0]) != expectedHost {
						return fmt.Errorf(
							"an expected host in oidc-apps HTTPRoute is not found, expected: %s, got: %s",
							expectedHost, string(httpRoute.Spec.Hostnames[0]),
						)
					}

					// Verify parentRefs are set
					if len(httpRoute.Spec.ParentRefs) == 0 {
						return errors.New("no parentRefs set on HTTPRoute")
					}

					return nil
				}

				return fmt.Errorf("an expected oidc-apps HTTPRoute: %s is not found", constants.HTTPRouteName+"-"+suffix)
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())
		})

		It("there shall be no oidc-apps annotated ingress present in the deployment namespace", func(ctx SpecContext) {
			suffix := randutils.GenerateSha256(strings.Join([]string{httpRouteTarget, defaultNamespace}, "-"))
			// HTTPRoute target has ingress.create=false, so no ingress should be created
			Eventually(func() error {
				ingress := &gatewayv1.HTTPRoute{}

				err := clt.Get(ctx,
					client.ObjectKey{
						Namespace: defaultNamespace,
						Name:      constants.IngressName + "-" + suffix,
					}, ingress)

				if apierrors.IsNotFound(err) {
					return nil
				}

				if err != nil {
					return err
				}

				return fmt.Errorf("unexpected oidc-apps ingress found: %s", constants.IngressName+"-"+suffix)
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())
		})

		It("there shall be an oauth2 service present in the deployment namespace", func(ctx SpecContext) {
			services := corev1.ServiceList{}
			suffix := randutils.GenerateSha256(strings.Join([]string{httpRouteTarget, defaultNamespace}, "-"))
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

				for _, service := range services.Items {
					if service.Name == constants.ServiceNameOauth2Service+"-"+suffix {
						return nil
					}
				}

				return fmt.Errorf("an expected oidc-apps service: %s is not found",
					constants.ServiceNameOauth2Service+"-"+suffix)
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())
		})
	}) // End of Context("when a deployment is a target with HTTPRoute enabled")

	Context("when HTTPRoute create is set to false", func() {
		BeforeAll(func(ctx SpecContext) {
			deployment := createHTTPRouteSkipTargetDeployment()
			Eventually(func() error {
				return clt.Create(ctx, deployment)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			replicaSet := createReplicaSet(deployment)
			Eventually(func() error {
				return clt.Create(ctx, replicaSet)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			pod := createPod(replicaSet)
			Eventually(func() error {
				return clt.Create(ctx, pod)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())
		}, NodeTimeout(5*time.Second))

		AfterAll(func(ctx SpecContext) {
			cleanUpAllDeployments(ctx)
		}, NodeTimeout(5*time.Second))

		It("there shall be auth & authz sidecar containers present in the deployment pod", func() {
			pod := &corev1.Pod{}
			d := hash5(client.ObjectKey{Name: httpRouteSkipTarget, Namespace: defaultNamespace})
			rs := hash5(client.ObjectKey{Name: strings.Join([]string{nginxRS, d}, "-"), Namespace: defaultNamespace})
			Expect(clt.Get(ctx,
				client.ObjectKey{
					Name:      strings.Join([]string{nginxPod, rs}, "-"),
					Namespace: defaultNamespace,
				},
				pod,
			)).To(Succeed())
			Expect(pod.Spec.Containers).Should(HaveLen(3))
		})

		It("there shall be no oidc-apps HTTPRoute present", func(ctx SpecContext) {
			httpRoutes := gatewayv1.HTTPRouteList{}
			suffix := randutils.GenerateSha256(strings.Join([]string{httpRouteSkipTarget, defaultNamespace}, "-"))

			Eventually(func() error {
				if err = clt.List(ctx, &httpRoutes,
					client.InNamespace(defaultNamespace),
					client.MatchingLabelsSelector{
						Selector: labels.SelectorFromSet(map[string]string{
							constants.LabelKey: constants.LabelValue,
						}),
					}); err != nil {
					return err
				}

				for _, httpRoute := range httpRoutes.Items {
					if httpRoute.Name == constants.HTTPRouteName+"-"+suffix {
						return fmt.Errorf("an unexpected oidc-apps HTTPRoute: %s is found",
							constants.HTTPRouteName+"-"+suffix)
					}
				}

				return nil
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())
		})
	}) // End of Context("when HTTPRoute create is set to false")

	Context("when a deployment is a target with HTTPRoute defaultPath", Ordered, func() {
		BeforeAll(func(ctx SpecContext) {
			deployment := createHTTPRouteDefaultPathTargetDeployment()
			Eventually(func() error {
				return clt.Create(ctx, deployment)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			replicaSet := createReplicaSet(deployment)
			Eventually(func() error {
				return clt.Create(ctx, replicaSet)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			pod := createPod(replicaSet)
			Eventually(func() error {
				return clt.Create(ctx, pod)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())
		}, NodeTimeout(5*time.Second))

		AfterAll(func(ctx SpecContext) {
			cleanUpAllDeployments(ctx)
		}, NodeTimeout(5*time.Second))

		It("there shall be an HTTPRoute with a redirect rule for defaultPath", func(ctx SpecContext) {
			httpRoutes := gatewayv1.HTTPRouteList{}
			suffix := randutils.GenerateSha256(strings.Join([]string{httpRouteDefaultPathTarget, defaultNamespace}, "-"))
			Eventually(func() error {
				if err = clt.List(ctx, &httpRoutes,
					client.InNamespace(defaultNamespace),
					client.MatchingLabelsSelector{
						Selector: labels.SelectorFromSet(map[string]string{
							constants.LabelKey: constants.LabelValue,
						}),
					}); err != nil {
					return err
				}

				for _, httpRoute := range httpRoutes.Items {
					if httpRoute.Name != constants.HTTPRouteName+"-"+suffix {
						continue
					}

					// With defaultPath, there should be 2 rules: redirect + backend
					if len(httpRoute.Spec.Rules) != 2 {
						return fmt.Errorf("expected 2 rules (redirect + backend), got %d", len(httpRoute.Spec.Rules))
					}

					// First rule should be the redirect
					redirectRule := httpRoute.Spec.Rules[0]
					if len(redirectRule.Filters) != 1 {
						return fmt.Errorf("expected 1 filter on redirect rule, got %d", len(redirectRule.Filters))
					}

					if redirectRule.Filters[0].Type != gatewayv1.HTTPRouteFilterRequestRedirect {
						return fmt.Errorf("expected RequestRedirect filter, got %s", redirectRule.Filters[0].Type)
					}

					redirect := redirectRule.Filters[0].RequestRedirect
					if redirect == nil || redirect.Path == nil || redirect.Path.ReplaceFullPath == nil {
						return errors.New("redirect filter path is not set")
					}

					if *redirect.Path.ReplaceFullPath != "/dashboard" {
						return fmt.Errorf("expected redirect to /dashboard, got %s", *redirect.Path.ReplaceFullPath)
					}

					// Second rule should be the catch-all backend
					if len(httpRoute.Spec.Rules[1].BackendRefs) == 0 {
						return errors.New("backend rule has no backendRefs")
					}

					return nil
				}

				return fmt.Errorf("HTTPRoute %s not found", constants.HTTPRouteName+"-"+suffix)
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())
		})
	}) // End of Context("when a deployment is a target with HTTPRoute defaultPath")
})

var _ = Describe("Oidc Apps HTTPRoute StatefulSet Target Test", Ordered, func() {
	Context("when a statefulSet is a target with HTTPRoute enabled", Ordered, func() {
		BeforeAll(func(ctx SpecContext) {
			statefulSet := createHTTPRouteTargetStatefulSet()
			Eventually(func() error {
				return clt.Create(ctx, statefulSet)
			}).WithPolling(100 * time.Millisecond).Should(Succeed())

			// Create 2 pods for the statefulset
			for i := range 2 {
				pod := createHTTPRouteStatefulSetPod(statefulSet, fmt.Sprintf("%d", i))
				Eventually(func() error {
					return clt.Create(ctx, pod)
				}).WithPolling(100 * time.Millisecond).Should(Succeed())
			}
		}, NodeTimeout(5*time.Second))

		AfterAll(func(ctx SpecContext) {
			cleanUpAllStatefulSets(ctx)
		}, NodeTimeout(5*time.Second))

		It("there shall be auth & authz sidecar containers present in the statefulSet pods", func() {
			for i := range 2 {
				pod := &corev1.Pod{}
				Expect(clt.Get(ctx,
					client.ObjectKey{
						Name:      strings.Join([]string{nginxPod, fmt.Sprintf("%d", i)}, "-"),
						Namespace: defaultNamespace,
					},
					pod,
				)).To(Succeed())
				Expect(pod.Spec.Containers).Should(HaveLen(3))
			}
		})

		It("there shall be oidc-apps HTTPRoutes present for each pod in the statefulSet namespace", func(ctx SpecContext) {
			httpRoutes := gatewayv1.HTTPRouteList{}
			Eventually(func() error {
				if err = clt.List(ctx, &httpRoutes,
					client.InNamespace(defaultNamespace),
					client.MatchingLabelsSelector{
						Selector: labels.SelectorFromSet(map[string]string{
							constants.LabelKey: constants.LabelValue,
						}),
					}); err != nil {
					return err
				}

				// For StatefulSets, one HTTPRoute per pod
				expectedCount := 2
				foundCount := 0

				for range httpRoutes.Items {
					foundCount++
				}

				if foundCount < expectedCount {
					return fmt.Errorf("expected at least %d HTTPRoutes, found %d", expectedCount, foundCount)
				}

				return nil
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())
		})

		It("there shall be oauth2 services present for each pod in the statefulSet namespace", func(ctx SpecContext) {
			services := corev1.ServiceList{}
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

				// For StatefulSets, one service per pod
				expectedCount := 2
				foundCount := 0

				for range services.Items {
					foundCount++
				}

				if foundCount < expectedCount {
					return fmt.Errorf("expected at least %d services, found %d", expectedCount, foundCount)
				}

				return nil
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())
		})
	}) // End of Context("when a statefulSet is a target with HTTPRoute enabled")
})
