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

package test

import (
	"context"
	_ "embed"
	"encoding/json"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/rand"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
	"os"
	"strings"

	"path/filepath"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/webhook"
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
)

var targetDeployment, nonTargetDeployment *appsv1.Deployment
var targetReplicaSet, nonTargetReplicaSet *appsv1.ReplicaSet
var targetPod, targetPodWithServiceAccount, podWithLessResources, podWithMoreResources, nonTargetPod *corev1.Pod
var podWebhook *webhook.PodMutator

var _ = BeforeEach(func() {

	initNonTargetDeployment()
	initTargetDeployment()

	s := runtime.NewScheme()
	err := scheme.AddToScheme(s)
	Expect(err).NotTo(HaveOccurred())

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(targetDeployment, targetReplicaSet, targetPod).
		WithObjects(podWithLessResources, podWithMoreResources, targetPodWithServiceAccount).
		WithObjects(nonTargetDeployment, nonTargetReplicaSet, nonTargetPod).
		Build()

	configuration.CreateControllerConfigOrDie(
		filepath.Join(tmpDir, "config.yaml"),
		configuration.WithClient(fakeClient),
		configuration.WithLog(_log),
	)

	podWebhook = &webhook.PodMutator{
		Client:  fakeClient,
		Decoder: admission.NewDecoder(s),
	}

})

func initTargetDeployment() {
	targetDeployment = &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "nginx",
			Labels:    map[string]string{"app": "nginx"},
			UID:       "target-deployment",
		},
	}
	targetReplicaSet = &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-rs-0001",
			Namespace: "nginx",
			UID:       "target-replicaset",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
					Name:       "nginx",
					UID:        "target-deployment",
				},
			},
		},
	}
	targetPod = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "nginx",
			UID:       "uid-pod",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       "nginx-rs-0001",
					UID:        "target-replicaset",
				},
			},
		},
	}

	targetPodWithServiceAccount = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-with-sa",
			Namespace: "nginx",
			UID:       "uid-pod",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       "nginx-rs-0001",
					UID:        "target-replicaset",
				},
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "nginx",
		},
	}

	podWithLessResources = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-with-less-resources",
			Namespace: "nginx",
			UID:       "uid-pod",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       "nginx-rs-0001",
					UID:        "target-replicaset",
				},
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "nginx",
				},
				{
					Name: constants.ContainerNameOauth2Proxy,
					Resources: corev1.ResourceRequirements{
						Requests: map[corev1.ResourceName]resource.Quantity{
							"cpu":    resource.MustParse("20m"),
							"memory": resource.MustParse("32Mi"),
						},
						Limits: map[corev1.ResourceName]resource.Quantity{
							"cpu":    resource.MustParse("200m"),
							"memory": resource.MustParse("64Mi"),
						},
					},
				},
			},
		},
	}

	podWithMoreResources = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-with-more-resources",
			Namespace: "nginx",
			UID:       "uid-pod",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       "nginx-rs-0001",
					UID:        "target-replicaset",
				},
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "nginx",
				},
				{
					Name: constants.ContainerNameOauth2Proxy,
					Resources: corev1.ResourceRequirements{
						Requests: map[corev1.ResourceName]resource.Quantity{
							"cpu":    resource.MustParse("500m"),
							"memory": resource.MustParse("300Mi"),
						},
						Limits: map[corev1.ResourceName]resource.Quantity{
							"cpu":    resource.MustParse("500m"),
							"memory": resource.MustParse("300Mi"),
						},
					},
				},
			},
		},
	}

}

func initNonTargetDeployment() {
	nonTargetDeployment = &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       "non-target-deployment",
		},
	}
	nonTargetReplicaSet = &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rs-0001",
			Namespace: "default",
			UID:       "non-target-replicaset",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
					Name:       "test",
					UID:        "non-target-deployment",
				},
			},
		},
	}

	nonTargetPod = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       "uid-pod",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       "tesst-rs-0001",
					UID:        "non-target-replicaset",
				},
			},
		},
	}
}

var _ = Describe("Oidc Apps MutatingAdmission Framework Test", func() {

	Context("when a pod belongs to a target", func() {
		It("there shall be auth & authz proxies in the patch pod spec", func() {
			patchedPod := patchPod(targetPod)
			_log.Info("patched pod", "patched pod", patchedPod)
			By("verifying containers in patched pod", func() {
				expectedContainerImages := []string{"kube-rbac-proxy-watcher", "oauth2-proxy"}
				Expect(len(patchedPod.Spec.Containers)).To(Equal(2))

				for _, c := range patchedPod.Spec.Containers {
					image, _, ok := strings.Cut(c.Image, ":")
					Expect(ok).To(BeTrue())
					n := strings.SplitAfter(image, "/")
					Expect(n[len(n)-1]).To(BeElementOf(expectedContainerImages))
				}
			}) //By
		}) //It
		It("there shall be a secret volumes in the target pod", func() {
			patchedPod := patchPod(targetPod)
			_log.Info("patched pod volumes", "patched pod", patchedPod.Spec.Volumes)
			Expect(patchedPod.Spec.Volumes).To(ContainElement(
				corev1.Volume{
					Name: constants.Oauth2VolumeName,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "oauth2-proxy-" + rand.GenerateSha256(targetDeployment.Name+"-"+targetDeployment.Namespace),
							Optional:   ptr.To(false),
						},
					},
				},
			))
			Expect(patchedPod.Spec.Volumes).To(ContainElement(
				corev1.Volume{
					Name: constants.KubeRbacProxyVolumeName,
					VolumeSource: corev1.VolumeSource{
						Projected: &corev1.ProjectedVolumeSource{
							Sources: []corev1.VolumeProjection{
								{
									Secret: &corev1.SecretProjection{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "resource-attributes-" + rand.GenerateSha256(targetDeployment.Name+"-"+targetDeployment.Namespace),
										},
										Optional: ptr.To(false),
									},
								},
								{
									Secret: &corev1.SecretProjection{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "oidc-ca-" + rand.GenerateSha256(targetDeployment.
												Name+"-"+targetDeployment.Namespace),
										},
										Optional: ptr.To(false),
									},
								},
							},
						},
					},
				},
			))
		})
		It("there shall be a volume mounts for auth & authz proxies", func() {
			patchedPod := patchPod(targetPod)
			for _, c := range patchedPod.Spec.Containers {
				_log.Info("patched pod container", "container", c)
				switch c.Name {
				case constants.ContainerNameOauth2Proxy:
					Expect(c.VolumeMounts).To(ContainElement(
						corev1.VolumeMount{
							Name:      constants.Oauth2VolumeName,
							ReadOnly:  true,
							MountPath: "/etc/oauth2-proxy.cfg",
							SubPath:   "oauth2-proxy.cfg",
						}))
				}
				switch c.Name {
				case constants.ContainerNameKubeRbacProxy:
					Expect(c.VolumeMounts).To(ContainElement(
						corev1.VolumeMount{
							Name:      constants.KubeRbacProxyVolumeName,
							ReadOnly:  true,
							MountPath: "/etc/kube-rbac-proxy",
						}))
				}
			}
		})
		When("the GARDEN_KUBECONFIG env variable is present", func() {
			It("there shall be a projected secret volume in the pod spec containing kubeconfig secret", func() {
				err := os.Setenv("GARDEN_KUBECONFIG", filepath.Join(tmpDir, "kubeconfig"))
				DeferCleanup(os.Unsetenv, "GARDEN_KUBECONFIG")
				Expect(err).NotTo(HaveOccurred())
				patchedPod := patchPod(targetPod)
				_log.Info("patched pod volumes", "patched pod", patchedPod.Spec.Volumes)
				Expect(patchedPod.Spec.Volumes).To(ContainElement(
					corev1.Volume{
						Name: constants.KubeRbacProxyVolumeName,
						VolumeSource: corev1.VolumeSource{
							Projected: &corev1.ProjectedVolumeSource{
								Sources: []corev1.VolumeProjection{
									{
										Secret: &corev1.SecretProjection{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "resource-attributes-" + rand.GenerateSha256(targetDeployment.Name+"-"+targetDeployment.Namespace),
											},
											Optional: ptr.To(false),
										},
									},
									{
										Secret: &corev1.SecretProjection{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "kubeconfig-" + rand.GenerateSha256(targetDeployment.
													Name+"-"+targetDeployment.Namespace),
											},
											Optional: ptr.To(false),
										},
									},
									{
										Secret: &corev1.SecretProjection{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "oidc-ca-" + rand.GenerateSha256(targetDeployment.
													Name+"-"+targetDeployment.Namespace),
											},
											Optional: ptr.To(false),
										},
									},
								},
							},
						},
					},
				))
			}) //It
		}) // When
		When("the target configuration has a oidcCABundle", func() {
			It("there shall be a projected secret volume in the pod spec containing oidc-ca secret", func() {
				patchedPod := patchPod(targetPod)
				_log.Info("patched pod volumes", "patched pod", patchedPod.Spec.Volumes)
				Expect(patchedPod.Spec.Volumes).To(ContainElement(
					corev1.Volume{
						Name: constants.KubeRbacProxyVolumeName,
						VolumeSource: corev1.VolumeSource{
							Projected: &corev1.ProjectedVolumeSource{
								Sources: []corev1.VolumeProjection{
									{
										Secret: &corev1.SecretProjection{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "resource-attributes-" + rand.GenerateSha256(targetDeployment.Name+"-"+targetDeployment.Namespace),
											},
											Optional: ptr.To(false),
										},
									},
									{
										Secret: &corev1.SecretProjection{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "oidc-ca-" + rand.GenerateSha256(targetDeployment.
													Name+"-"+targetDeployment.Namespace),
											},
											Optional: ptr.To(false),
										},
									},
								},
							},
						},
					},
				))
			}) //It
		}) //When
		When("there is a container resource defined in the incoming request which are less than default", func() {
			It("shall modify the container resources", func() {
				pp := patchPod(podWithLessResources)
				_log.Info("patched pod", "patched pod", pp)

				for _, c := range pp.Spec.Containers {
					switch c.Name {
					case constants.ContainerNameOauth2Proxy:
						Expect(c.Resources).To(Equal(corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								"cpu":    resource.MustParse("100m"),
								"memory": resource.MustParse("100Mi"),
							},
							Requests: corev1.ResourceList{
								"cpu":    resource.MustParse("50m"),
								"memory": resource.MustParse("50Mi"),
							},
							Claims: nil,
						}))
					}
				}
			})
		}) //When there is a container resource defined in the incoming request
		When("there is a container resource defined in the incoming request which are bigger than default", func() {
			It("shall not modify the container resources", func() {
				pp := patchPod(podWithMoreResources)
				_log.Info("patched pod", "patched pod", pp)

				for _, c := range pp.Spec.Containers {
					switch c.Name {
					case constants.ContainerNameOauth2Proxy:
						Expect(c.Resources).To(Equal(podWithMoreResources.Spec.Containers[1].Resources))
					}
				}
			})
		}) //
		When("there isn't any container resource defined in the incoming request", func() {
			It("shall set the default container resources", func() {
				pp := patchPod(podWithLessResources)
				_log.Info("patched pod", "patched pod", pp)

				for _, c := range pp.Spec.Containers {
					switch c.Name {
					case constants.ContainerNameKubeRbacProxy:
						expected := corev1.ResourceRequirements{
							Limits: map[corev1.ResourceName]resource.Quantity{
								"cpu":    resource.MustParse("100m"),
								"memory": resource.MustParse("100Mi"),
							},
							Requests: map[corev1.ResourceName]resource.Quantity{
								"cpu":    resource.MustParse("50m"),
								"memory": resource.MustParse("50Mi"),
							}}
						Expect(c.Resources).To(Equal(expected))
					}
				}
			})
		}) //When there isn't any container resource defined in the incoming request
	}) //Context
	Context("when a pod does not belong to a target", func() {
		It("there shall be no auth & authz proxies in the pod templates spec", func() {
			raw, err := json.Marshal(nonTargetPod)
			Expect(err).NotTo(HaveOccurred())
			req := admission.Request{
				AdmissionRequest: adminssionv1.AdmissionRequest{
					UID:       "uid-request",
					Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
					Resource:  metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
					Namespace: "default",
					Operation: adminssionv1.Create,
					Object: runtime.RawExtension{
						Raw: raw,
					},
				},
			}
			resp := podWebhook.Handle(context.Background(), req)
			_log.Info("response", "response", resp.String())
			Expect(resp.Allowed).To(BeTrue())
			Expect(resp.Patches).To(BeNil())
		}) //It
	}) //Context when a pod does not belong to a target
}) //Describe

func patchPod(pod *corev1.Pod) *corev1.Pod {
	raw, err := json.Marshal(pod)
	Expect(err).NotTo(HaveOccurred())
	req := admission.Request{
		AdmissionRequest: adminssionv1.AdmissionRequest{
			UID:       "uid-request",
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Resource:  metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			Namespace: "nginx",
			Operation: adminssionv1.Create,
			Object: runtime.RawExtension{
				Raw: raw,
			},
		},
	}
	resp := podWebhook.Handle(context.Background(), req)
	_log.Info("response", "response", resp.String())
	Expect(resp.Allowed).To(BeTrue())
	Expect(resp.Patches).NotTo(BeNil())

	patchBytes, err := json.Marshal(resp.Patches)
	Expect(err).NotTo(HaveOccurred())
	decodedPatch, err := jsonpatch.DecodePatch(patchBytes)
	Expect(err).NotTo(HaveOccurred())

	// Apply the patch
	patchPodBytes, err := decodedPatch.Apply(raw)
	Expect(err).NotTo(HaveOccurred())
	var patchedPod = &corev1.Pod{}
	err = json.Unmarshal(patchPodBytes, &patchedPod)
	Expect(err).NotTo(HaveOccurred())

	return patchedPod
}
