// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/onsi/gomega"

	istionetv1alpha3 "istio.io/api/networking/v1alpha3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/oidc-apps-controller/pkg/constants"
)

func TestIstioGatewayNameConstant(t *testing.T) {
	g := NewWithT(t)
	g.Expect(constants.IstioGatewayName).To(Equal("oauth2-gateway"))
}

func TestIstioGatewayLabelConstant(t *testing.T) {
	g := NewWithT(t)
	g.Expect(constants.LabelKey).To(Equal("oidc-application-controller/component"))
	g.Expect(constants.LabelValue).To(Equal("oidc-apps"))
}

func TestIstioVirtualServiceLabels(t *testing.T) {
	t.Run("IstioVirtualService has correct labels", func(t *testing.T) {
		assert.Equal(t, "oidc-application-controller/component", constants.LabelKey)
		assert.Equal(t, "oidc-apps", constants.LabelValue)
	})
}

func TestIstioVirtualServiceNameConstant(t *testing.T) {
	t.Run("IstioVirtualService name constant is correct", func(t *testing.T) {
		assert.Equal(t, "oauth2-virtualservice", constants.IstioVirtualServiceName)
	})
}

func TestCreateIstioDestinationRuleForDeployment(t *testing.T) {
	g := NewWithT(t)

	deploy := &appsv1.Deployment{}
	deploy.SetName("test-deploy")
	deploy.SetNamespace("test-ns")

	dr := createIstioDestinationRuleForDeployment(deploy)

	g.Expect(dr.Namespace).To(Equal("test-ns"))
	g.Expect(dr.Labels).To(HaveKeyWithValue(constants.LabelKey, constants.LabelValue))
	g.Expect(dr.Spec.ExportTo).To(Equal([]string{"*"}))
	g.Expect(dr.Spec.Host).To(ContainSubstring("test-ns.svc.cluster.local"))
	g.Expect(dr.Spec.Host).To(HavePrefix(constants.ServiceNameOauth2Service))
	// TrafficPolicy must explicitly disable upstream TLS so the istio-ingressgateway
	// speaks plaintext to the oauth2-proxy upstream (which has no sidecar).
	g.Expect(dr.Spec.TrafficPolicy).NotTo(BeNil())
	g.Expect(dr.Spec.TrafficPolicy.Tls).NotTo(BeNil())
	g.Expect(dr.Spec.TrafficPolicy.Tls.Mode).To(Equal(istionetv1alpha3.ClientTLSSettings_DISABLE))
}

func TestCreateIstioDestinationRuleForStatefulSetPod(t *testing.T) {
	g := NewWithT(t)

	pod := &corev1.Pod{}
	pod.SetName("prometheus-0")
	pod.SetNamespace("shoot-ns")
	pod.SetAnnotations(map[string]string{
		constants.AnnotationHostKey: "prometheus.ingress.local.seed.local.gardener.cloud",
	})

	sts := &appsv1.StatefulSet{}
	sts.SetName("prometheus")
	sts.SetNamespace("shoot-ns")

	dr := createIstioDestinationRuleForStatefulSetPod(pod, sts)

	g.Expect(dr.Namespace).To(Equal("shoot-ns"))
	g.Expect(dr.Labels).To(HaveKeyWithValue(constants.LabelKey, constants.LabelValue))
	g.Expect(dr.Spec.ExportTo).To(Equal([]string{"*"}))
	g.Expect(dr.Spec.Host).To(ContainSubstring("shoot-ns.svc.cluster.local"))
	g.Expect(dr.Spec.Host).To(HavePrefix(constants.ServiceNameOauth2Service))
	g.Expect(dr.Spec.TrafficPolicy).NotTo(BeNil())
	g.Expect(dr.Spec.TrafficPolicy.Tls).NotTo(BeNil())
	g.Expect(dr.Spec.TrafficPolicy.Tls.Mode).To(Equal(istionetv1alpha3.ClientTLSSettings_DISABLE))
}
