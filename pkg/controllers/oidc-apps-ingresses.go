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
	"fmt"
	"strings"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	constants "github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/rand"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func createIngressForDeployment(object client.Object) (networkingv1.Ingress, error) {
	suffix := rand.GenerateSha256(object.GetName() + "-" + object.GetNamespace())
	ingressClassName := configuration.GetOIDCAppsControllerConfig().GetIngressClassName(object)
	ingressTLSSecretName := configuration.GetOIDCAppsControllerConfig().GetIngressTLSSecretName(object)
	host := configuration.GetOIDCAppsControllerConfig().GetHost(object)

	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.IngressName + "-" + suffix,
			Namespace: object.GetNamespace(),
			Labels:    map[string]string{constants.LabelKey: constants.LabelValue},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To(ingressClassName),
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{host},
					SecretName: ingressTLSSecretName,
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: host,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptr.To(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: constants.ServiceNameOauth2Service + "-" + suffix,
											Port: networkingv1.ServiceBackendPort{
												Name: "http",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if annotations := configuration.GetOIDCAppsControllerConfig().GetIngressAnnotations(object); len(annotations) > 0 {
		ingress.ObjectMeta.Annotations = annotations
	}

	return ingress, nil
}

func createIngressForStatefulSetPod(pod *corev1.Pod, object client.Object) (networkingv1.Ingress, error) {
	suffix := rand.GenerateSha256(pod.GetName() + "-" + pod.GetNamespace())
	ingressClassName := configuration.GetOIDCAppsControllerConfig().GetIngressClassName(object)
	ingressTLSSecretName := configuration.GetOIDCAppsControllerConfig().GetIngressTLSSecretName(object)
	hostPrefix, ok := pod.GetAnnotations()[constants.AnnotationHostKey]
	if !ok {
		return networkingv1.Ingress{}, fmt.Errorf("host annotation not found in pod %s/%s", pod.GetNamespace(), pod.GetName())
	}
	host, domain, _ := strings.Cut(hostPrefix, ".")
	index := fetchStrIndexIfPresent(pod)

	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.IngressName + "-" + addOptionalIndex(index+"-") + suffix,
			Namespace: object.GetNamespace(),
			Labels:    map[string]string{constants.LabelKey: constants.LabelValue},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To(ingressClassName),
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{fmt.Sprintf("%s-%s.%s", host, fetchStrIndexIfPresent(pod), domain)},
					SecretName: ingressTLSSecretName,
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: fmt.Sprintf("%s-%s.%s", host, fetchStrIndexIfPresent(pod), domain),
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptr.To(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: constants.ServiceNameOauth2Service + "-" + addOptionalIndex(
												index+"-") + suffix,
											Port: networkingv1.ServiceBackendPort{
												Name: "http",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	if annotations := configuration.GetOIDCAppsControllerConfig().GetIngressAnnotations(object); len(annotations) > 0 {
		ingress.ObjectMeta.Annotations = annotations
	}
	return ingress, nil
}
