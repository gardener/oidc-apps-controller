// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
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
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	autoscalerv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/webhook"
)

var targetVPA, nonTargetVpa *autoscalerv1.VerticalPodAutoscaler
var vpaWebhook *webhook.VPAMutator

var _ = BeforeEach(func() {
	s := runtime.NewScheme()
	err := scheme.AddToScheme(s)
	Expect(err).NotTo(HaveOccurred())
	err = autoscalerv1.AddToScheme(s)
	Expect(err).NotTo(HaveOccurred())

	initTargetDeployment()
	initNonTargetDeployment()
	initTargetVPA()
	initNonTargetVPA()

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(targetDeployment, targetReplicaSet, targetPod).
		WithObjects(targetVPA).
		WithObjects(nonTargetDeployment, nonTargetReplicaSet, nonTargetPod).
		WithObjects(nonTargetVpa).
		Build()

	configuration.CreateControllerConfigOrDie(
		filepath.Join(tmpDir, "config.yaml"),
		configuration.WithClient(fakeClient),
		configuration.WithLog(_log),
	)

	vpaWebhook = &webhook.VPAMutator{
		Client:  fakeClient,
		Decoder: admission.NewDecoder(s),
	}
})

func initTargetVPA() {
	targetVPA = &autoscalerv1.VerticalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-vpa",
			Namespace: "nginx",
			Labels:    map[string]string{"app": "nginx"},
		},
		Spec: autoscalerv1.VerticalPodAutoscalerSpec{
			TargetRef: &autoscalingv1.CrossVersionObjectReference{
				Kind:       "Deployment",
				Name:       "nginx",
				APIVersion: "apps/v1",
			},
			UpdatePolicy: &autoscalerv1.PodUpdatePolicy{
				UpdateMode: ptr.To(autoscalerv1.UpdateModeRecreate),
			},
			ResourcePolicy: &autoscalerv1.PodResourcePolicy{
				ContainerPolicies: []autoscalerv1.ContainerResourcePolicy{
					{
						ContainerName: "nginx",
						MinAllowed: corev1.ResourceList{
							"cpu":    resource.MustParse("100m"),
							"memory": resource.MustParse("100Mi"),
						},
					},
				},
			},
		},
	}
}

func initNonTargetVPA() {
	nonTargetVpa = &autoscalerv1.VerticalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vpa",
			Namespace: "default",
		},
		Spec: autoscalerv1.VerticalPodAutoscalerSpec{
			TargetRef: &autoscalingv1.CrossVersionObjectReference{
				Kind:       "Deployment",
				Name:       "test",
				APIVersion: "apps/v1",
			},
			UpdatePolicy: &autoscalerv1.PodUpdatePolicy{
				UpdateMode: ptr.To(autoscalerv1.UpdateModeRecreate),
			},
			ResourcePolicy: &autoscalerv1.PodResourcePolicy{
				ContainerPolicies: []autoscalerv1.ContainerResourcePolicy{
					{
						ContainerName: "test",
						MinAllowed: corev1.ResourceList{
							"cpu":    resource.MustParse("100m"),
							"memory": resource.MustParse("100Mi"),
						},
					},
				},
			},
		},
	}
}

var _ = Describe("Oidc Apps MutatingAdmission Framework Test", func() {
	Context("when the reconciled target has vpa", func() {
		It("It shall contain mode=Off for auth & autz proxies", func() {
			patchedVpa := patchVpa(targetVPA)
			_log.Info("patched pod", "patched vpa", patchedVpa)
			Expect(patchedVpa.Spec.ResourcePolicy.ContainerPolicies).To(HaveLen(3))
			Expect(patchedVpa.Spec.ResourcePolicy.ContainerPolicies).To(ContainElement(autoscalerv1.ContainerResourcePolicy{
				ContainerName: constants.ContainerNameOauth2Proxy,
				Mode:          ptr.To(autoscalerv1.ContainerScalingModeOff),
			}))
			Expect(patchedVpa.Spec.ResourcePolicy.ContainerPolicies).To(ContainElement(autoscalerv1.ContainerResourcePolicy{
				ContainerName: constants.ContainerNameKubeRbacProxy,
				Mode:          ptr.To(autoscalerv1.ContainerScalingModeOff),
			}))
		})
	})

	Context("when a reconciled target does not belong to a target", func() {
		It("there shall be no auth & authz policies in the vpa spec", func() {
			raw, err := json.Marshal(nonTargetVpa)
			Expect(err).NotTo(HaveOccurred())
			req := admission.Request{
				AdmissionRequest: adminssionv1.AdmissionRequest{
					UID:       "uid-request",
					Kind:      metav1.GroupVersionKind{Group: "autoscaling.k8s.io", Version: "v1", Kind: "VerticalPodAutoscaler"},
					Resource:  metav1.GroupVersionResource{Group: "autoscaling.k8s.io", Version: "v1", Resource: "verticalpodautoscalers"},
					Namespace: "default",
					Operation: adminssionv1.Update,
					Object: runtime.RawExtension{
						Raw: raw,
					},
				},
			}
			resp := vpaWebhook.Handle(context.Background(), req)
			_log.Info("response", "response", resp.String())
			Expect(resp.Allowed).To(BeTrue())
			Expect(resp.Patches).To(BeNil())
		}) // It
	})
})

func patchVpa(vpa *autoscalerv1.VerticalPodAutoscaler) *autoscalerv1.VerticalPodAutoscaler {
	raw, err := json.Marshal(vpa)

	Expect(err).NotTo(HaveOccurred())

	req := admission.Request{
		AdmissionRequest: adminssionv1.AdmissionRequest{
			UID:       "uid-request",
			Kind:      metav1.GroupVersionKind{Group: "autoscaling.k8s.io", Version: "v1", Kind: "VerticalPodAutoscaler"},
			Resource:  metav1.GroupVersionResource{Group: "autoscaling.k8s.io", Version: "v1", Resource: "verticalpodautoscalers"},
			Namespace: "nginx",
			Operation: adminssionv1.Update,
			Object: runtime.RawExtension{
				Raw: raw,
			},
		},
	}
	resp := vpaWebhook.Handle(context.Background(), req)
	_log.Info("response", "response", resp.String())
	Expect(resp.Allowed).To(BeTrue())
	Expect(resp.Patches).NotTo(BeNil())

	patchBytes, err := json.Marshal(resp.Patches)
	Expect(err).NotTo(HaveOccurred())
	decodedPatch, err := jsonpatch.DecodePatch(patchBytes)
	Expect(err).NotTo(HaveOccurred())

	// Apply the patch
	patchVpaBytes, err := decodedPatch.Apply(raw)
	Expect(err).NotTo(HaveOccurred())

	var patchedVpa = &autoscalerv1.VerticalPodAutoscaler{}

	err = json.Unmarshal(patchVpaBytes, &patchedVpa)
	Expect(err).NotTo(HaveOccurred())

	return patchedVpa
}
