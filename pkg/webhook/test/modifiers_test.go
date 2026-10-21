// SPDX-FileCopyrightText: Contributors to the Gardener project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"context"
	"encoding/json"
	"path/filepath"

	jsonpatch "github.com/evanphx/json-patch"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	adminssionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/webhook"
)

var _ = Describe("Cookie Secret Injection Tests", func() {
	Context("when the oauth2-proxy container is injected", func() {
		var (
			deployment1      *appsv1.Deployment
			replicaSet1      *appsv1.ReplicaSet
			pod1             *corev1.Pod
			localPodWebhook1 *webhook.PodMutator
		)

		BeforeEach(func() {
			deployment1 = &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "nginx",
					Labels:    map[string]string{"app": "nginx"},
					UID:       "deployment-uid-1",
				},
			}
			replicaSet1 = &appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-rs-0001",
					Namespace: "nginx",
					UID:       "replicaset-uid-1",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "apps/v1",
							Kind:       "Deployment",
							Name:       "nginx",
							UID:        "deployment-uid-1",
						},
					},
				},
			}
			pod1 = &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-pod-1",
					Namespace: "nginx",
					UID:       "pod-uid-1",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "apps/v1",
							Kind:       "ReplicaSet",
							Name:       "nginx-rs-0001",
							UID:        "replicaset-uid-1",
						},
					},
				},
			}

			s := runtime.NewScheme()
			err := scheme.AddToScheme(s)
			Expect(err).NotTo(HaveOccurred())

			fakeClient := fake.NewClientBuilder().
				WithScheme(s).
				WithObjects(deployment1, replicaSet1, pod1).
				Build()

			configuration.CreateControllerConfigOrDie(
				filepath.Join(tmpDir, "config.yaml"),
				configuration.WithClient(fakeClient),
				configuration.WithLog(_log),
			)

			localPodWebhook1 = &webhook.PodMutator{
				Client:  fakeClient,
				Decoder: admission.NewDecoder(s),
			}
		})

		It("should point oauth2-proxy at the mounted cookie-secret file", func() {
			patchedPod := patchPodWithWebhook(pod1, localPodWebhook1)
			args := oauth2ProxyArgs(patchedPod)

			Expect(args).To(ContainElement("--cookie-secret-file=/etc/oauth2-proxy/"+constants.CookieSecretKey),
				"oauth2-proxy should read the cookie secret from the mounted file")
		})

		It("should not pass the cookie secret as an inline argument", func() {
			patchedPod := patchPodWithWebhook(pod1, localPodWebhook1)
			args := oauth2ProxyArgs(patchedPod)

			for _, arg := range args {
				Expect(arg).NotTo(HavePrefix("--cookie-secret="),
					"the cookie secret must not be injected as a container argument")
			}
		})
	})
})

var _ = Describe("Webhook host annotation Tests", func() {
	Context("when HTTPRoute is enabled, host annotation uses HTTPRoute hostPrefix", func() {
		var (
			deployment      *appsv1.Deployment
			replicaSet      *appsv1.ReplicaSet
			pod             *corev1.Pod
			localPodWebhook *webhook.PodMutator
			savedGlobal     configuration.Global
			savedTargets    []configuration.Target
		)

		BeforeEach(func() {
			deployment = &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "nginx",
					Labels:    map[string]string{"app": "nginx"},
					UID:       "deployment-uid-httproute",
				},
			}
			replicaSet = &appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-rs-0001",
					Namespace: "nginx",
					UID:       "replicaset-uid-httproute",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "apps/v1",
							Kind:       "Deployment",
							Name:       "nginx",
							UID:        "deployment-uid-httproute",
						},
					},
				},
			}
			pod = &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-pod-1",
					Namespace: "nginx",
					UID:       "pod-uid-httproute",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "apps/v1",
							Kind:       "ReplicaSet",
							Name:       "nginx-rs-0001",
							UID:        "replicaset-uid-httproute",
						},
					},
				},
			}

			s := runtime.NewScheme()
			err := scheme.AddToScheme(s)
			Expect(err).NotTo(HaveOccurred())

			fakeClient := fake.NewClientBuilder().
				WithScheme(s).
				WithObjects(deployment, replicaSet, pod).
				Build()

			cfg := configuration.GetOIDCAppsControllerConfig()
			savedGlobal = cfg.Global
			savedTargets = cfg.Targets

			cfg.Global = configuration.Global{
				DomainName: "example.org",
				HTTPRoutes: &configuration.HTTPRoutesGlobalConf{Enabled: true},
				Oauth2Proxy: &configuration.Oauth2ProxyConfig{
					ClientID:      "client-id",
					ClientSecret:  "client-secret",
					OidcIssuerURL: "https://oidc-provider.org",
				},
			}
			cfg.Targets = []configuration.Target{
				{
					Name: "nginx",
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "nginx"},
					},
					HTTPRoute: &configuration.HTTPRouteConf{
						Create:     true,
						HostPrefix: "my-httproute-prefix",
					},
				},
			}
			cfg.SetClient(fakeClient)

			localPodWebhook = &webhook.PodMutator{
				Client:  fakeClient,
				Decoder: admission.NewDecoder(s),
			}
		})

		It("should set the host annotation with the HTTPRoute hostPrefix", func() {
			patchedPod := patchPodWithWebhook(pod, localPodWebhook)

			hostAnnotation := patchedPod.GetAnnotations()[constants.AnnotationHostKey]
			Expect(hostAnnotation).NotTo(BeEmpty(), "Host annotation should be set")
			Expect(hostAnnotation).To(HavePrefix("my-httproute-prefix-"),
				"Host annotation should use the HTTPRoute hostPrefix")
			Expect(hostAnnotation).To(HaveSuffix(".example.org"),
				"Host annotation should include the global domain")
		})

		AfterEach(func() {
			cfg := configuration.GetOIDCAppsControllerConfig()
			cfg.Global = savedGlobal
			cfg.Targets = savedTargets
		})
	})
})

// oauth2ProxyArgs returns the args of the oauth2-proxy container in the given pod.
func oauth2ProxyArgs(pod *corev1.Pod) []string {
	for _, container := range pod.Spec.Containers {
		if container.Name == constants.ContainerNameOauth2Proxy {
			return container.Args
		}
	}

	return nil
}

// Helper function to patch pod with a specific webhook
func patchPodWithWebhook(pod *corev1.Pod, wh *webhook.PodMutator) *corev1.Pod {
	return patchPodWithNamespaceOperationAndWebhook(pod, pod.Namespace, adminssionv1.Create, wh)
}

// Helper function to patch pod with namespace, operation, and webhook
func patchPodWithNamespaceOperationAndWebhook(pod *corev1.Pod, namespace string, operation adminssionv1.Operation, wh *webhook.PodMutator) *corev1.Pod {
	raw, err := json.Marshal(pod)
	Expect(err).NotTo(HaveOccurred())

	req := admission.Request{
		AdmissionRequest: adminssionv1.AdmissionRequest{
			UID:       "uid-request",
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Resource:  metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			Namespace: namespace,
			Operation: operation,
			Object: runtime.RawExtension{
				Raw: raw,
			},
		},
	}

	resp := wh.Handle(context.Background(), req)
	_log.Info("webhook response", "response", resp.String())
	Expect(resp.Allowed).To(BeTrue())

	// If no patches, return original pod
	if resp.Patches == nil {
		return pod
	}

	patchBytes, err := json.Marshal(resp.Patches)
	Expect(err).NotTo(HaveOccurred())
	decodedPatch, err := jsonpatch.DecodePatch(patchBytes)
	Expect(err).NotTo(HaveOccurred())

	// Apply the patch
	patchedPodBytes, err := decodedPatch.Apply(raw)
	Expect(err).NotTo(HaveOccurred())

	var patchedPod = &corev1.Pod{}

	err = json.Unmarshal(patchedPodBytes, &patchedPod)
	Expect(err).NotTo(HaveOccurred())

	return patchedPod
}
