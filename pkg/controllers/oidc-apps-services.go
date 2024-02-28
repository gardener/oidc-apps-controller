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
	"strings"

	constants "github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/rand"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func createOauth2Service(selectors client.MatchingLabels, object client.Object) (corev1.Service, error) {
	suffix := rand.GenerateSha256(object.GetName() + "-" + object.GetNamespace())
	index := fetchStrIndexIfPresent(object)

	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ServiceNameOauth2Service + "-" + addOptionalIndex(index+"-") + suffix,
			Namespace: object.GetNamespace(),
			Labels:    map[string]string{constants.LabelKey: constants.LabelValue},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					// The Oauth2 Sidecar port definition
					Name:       "http",
					Port:       8080,
					TargetPort: intstr.FromString("oauth2"),
				},
			},
			Selector: selectors,
		},
	}, nil
}

func fetchStrIndexIfPresent(object client.Object) string {
	idx, present := object.GetLabels()["statefulset.kubernetes.io/pod-name"]
	if present {
		l := strings.Split(idx, "-")
		return l[len(l)-1]
	}
	return ""
}
