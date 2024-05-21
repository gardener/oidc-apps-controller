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
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
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
								Namespace: "default",
								Path:      ptr.To("oidc-mutate-v1-pod"),
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

func createDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
			Labels:    map[string]string{"app": "nginx"},
			UID:       "1234",
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "nginx"},
			},
			Replicas: ptr.To(int32(1)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
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
			},
		},
	}
}

func createReplicaSet(deployment client.Object) *appsv1.ReplicaSet {
	// Create a ReplicaSet with owner reference to the Deployment
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-replicaset",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(deployment, appsv1.SchemeGroupVersion.WithKind("Deployment")),
			},
			UID: "5678",
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "nginx"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
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
			},
		},
	}
}

func createPod(replicaSet client.Object) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-pod",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(replicaSet, appsv1.SchemeGroupVersion.WithKind("ReplicaSet")),
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
