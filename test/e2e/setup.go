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
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/rand"
)

const (
	defaultNamespace  = "default"
	target            = "nginx-target"
	nonTarget         = "nginx-non-target"
	skipIngressTarget = "nginx-target-skip-ingress"
	nginxPod          = "nginx-pod"
	nginxRS           = "nginx-rs"
)

func installWebHooks(env *envtest.Environment) {
	env.WebhookInstallOptions = envtest.WebhookInstallOptions{
		MutatingWebhooks: []*admissionv1.MutatingWebhookConfiguration{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "oidc-apps-controller-pods.gardener.cloud",
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "MutatingWebhookConfiguration",
					APIVersion: "admissionregistration.k8s.io/v1",
				},
				Webhooks: []admissionv1.MutatingWebhook{
					{
						Name: "oidc-apps-deployments.gardener.cloud",
						Rules: []admissionv1.RuleWithOperations{
							{
								Operations: []admissionv1.OperationType{"CREATE", "UPDATE"},
								Rule: admissionv1.Rule{
									APIGroups:   []string{""},
									APIVersions: []string{"v1"},
									Resources:   []string{"pods"},
									Scope:       ptr.To(admissionv1.NamespacedScope),
								},
							},
						},
						FailurePolicy: ptr.To(admissionv1.Fail),
						MatchPolicy:   ptr.To(admissionv1.Equivalent),
						SideEffects:   ptr.To(admissionv1.SideEffectClassNone),
						ClientConfig: admissionv1.WebhookClientConfig{
							Service: &admissionv1.ServiceReference{
								Name:      "webhook-service",
								Namespace: defaultNamespace,
								Path:      ptr.To(constants.PodWebHookPath),
							},
						},
						AdmissionReviewVersions: []string{"v1"},
						TimeoutSeconds:          ptr.To(int32(20)),
					},
				},
			},
		},
	}
}

func createTargetDeployments() []*appsv1.Deployment {
	// Create a list of deployments with the target label
	deployments := []*appsv1.Deployment{
		{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      target,
				Namespace: defaultNamespace,
				Labels:    map[string]string{"app": target},
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": target},
				},
				Replicas: ptr.To(int32(1)),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": target},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "nginx",
								Image: "nginx:latest",
							},
						},
					},
				},
			},
		},
		{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      skipIngressTarget,
				Namespace: defaultNamespace,
				Labels:    map[string]string{"app": skipIngressTarget},
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": skipIngressTarget},
				},
				Replicas: ptr.To(int32(1)),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": skipIngressTarget},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "nginx",
								Image: "nginx:latest",
							},
						},
					},
				},
			},
		},
	}

	return deployments
}

func hash5(obj client.ObjectKey) string {
	// Create a hash from the object name
	return rand.GenerateSha256(strings.Join([]string{obj.Name, obj.Namespace}, "-"))
}

func createReplicaSet(owner client.Object) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{nginxRS, hash5(client.ObjectKeyFromObject(owner))}, "-"),
			Namespace: defaultNamespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(owner, appsv1.SchemeGroupVersion.WithKind("Deployment")),
			},
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": hash5(client.ObjectKeyFromObject(owner))},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": hash5(client.ObjectKeyFromObject(owner))},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:latest",
						},
					},
				},
			},
		},
	}
}

func createPod(owner client.Object) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{nginxPod, hash5(client.ObjectKeyFromObject(owner))}, "-"),
			Namespace: defaultNamespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(owner, appsv1.SchemeGroupVersion.WithKind("ReplicaSet")),
			},
			Labels: map[string]string{"app": "nginx"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:latest",
				},
			},
		},
	}
}

func createNonTargetDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      nonTarget,
			Namespace: defaultNamespace,
			Labels:    map[string]string{"app": nonTarget},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": nonTarget},
			},
			Replicas: ptr.To(int32(1)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": nonTarget},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:latest",
						},
					},
				},
			},
		},
	}
}

func createTargetStatefulSet() *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "StatefulSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      target,
			Namespace: defaultNamespace,
			Labels:    map[string]string{"app": target},
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": target},
			},
			Replicas: ptr.To(int32(1)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": target},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:latest",
						},
					},
				},
			},
		},
	}
}

func createTargetSkipIngressStatefulSet() *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "StatefulSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      skipIngressTarget,
			Namespace: defaultNamespace,
			Labels:    map[string]string{"app": skipIngressTarget},
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": skipIngressTarget},
			},
			Replicas: ptr.To(int32(1)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": skipIngressTarget},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:latest",
						},
					},
				},
			},
		},
	}
}

func createStatefulSetPod(owner client.Object, index string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{nginxPod, index}, "-"),
			Namespace: defaultNamespace,
			Labels: map[string]string{
				"app":                                target,
				"statefulset.kubernetes.io/pod-name": strings.Join([]string{nginxPod, index}, "-"),
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(owner, appsv1.SchemeGroupVersion.WithKind("StatefulSet")),
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:latest",
				},
			},
		},
	}
}

func createSkipIngressStatefulSetPod(owner client.Object, index string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{nginxPod, index}, "-"),
			Namespace: defaultNamespace,
			Labels: map[string]string{
				"app":                                skipIngressTarget,
				"statefulset.kubernetes.io/pod-name": strings.Join([]string{nginxPod, index}, "-"),
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(owner, appsv1.SchemeGroupVersion.WithKind("StatefulSet")),
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:latest",
				},
			},
		},
	}
}
