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
	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/constants"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func createIngress(host string, index string, object client.Object) (networkingv1.Ingress, error) {
	suffix, ok := object.GetAnnotations()[oidc_apps_controller.AnnotationSuffixKey]
	if !ok {
		return networkingv1.Ingress{}, fmt.Errorf("missing suffix annotation")
	}
	ingressClassName := configuration.GetOIDCAppsControllerConfig().GetIngressClassName(object)
	ingressTLSSecretName := configuration.GetOIDCAppsControllerConfig().GetIngressTLSSecretName(object)

	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-" + addOptionalIndex(index+"-") + suffix,
			Namespace: object.GetNamespace(),
			Labels:    map[string]string{oidc_apps_controller.LabelKey: "oauth2"},
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
											Name: "oauth2-service-" + addOptionalIndex(index+"-") + suffix,
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
	}, nil
}
