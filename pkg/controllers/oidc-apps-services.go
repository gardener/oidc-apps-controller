// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/rand"
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
