// SPDX-FileCopyrightText: Contributors to the Gardener project
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"testing"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	istionetv1alpha3 "istio.io/api/networking/v1alpha3"
	istioclientnetv1 "istio.io/client-go/pkg/apis/networking/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
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

func TestBuildIstioGatewayDenyRules(t *testing.T) {
	g := NewWithT(t)

	rules := buildIstioGatewayDenyRules(
		[]string{"/debug/", "/proxy/unsaved"},
		[]configuration.DeniedRoute{
			{Path: "/api/v1/", Methods: []string{"POST", "delete"}},
			{Path: "/admin/"},
		},
	)

	// deniedPaths render first, in order, then deniedRoutes.
	g.Expect(rules).To(HaveLen(4))

	for _, r := range rules {
		g.Expect(r.DirectResponse.Status).To(Equal(uint32(403)))
	}

	g.Expect(rules[0].Match).To(HaveLen(1))
	g.Expect(rules[0].Match[0].Uri.GetPrefix()).To(Equal("/debug/"))
	g.Expect(rules[0].Match[0].Method).To(BeNil())
	g.Expect(rules[1].Match).To(HaveLen(1))
	g.Expect(rules[1].Match[0].Uri.GetPrefix()).To(Equal("/proxy/unsaved"))

	// A route with methods emits one exact, upper-cased method match per method, each alongside the URI prefix.
	g.Expect(rules[2].Match).To(HaveLen(2))

	for i, method := range []string{"POST", "DELETE"} {
		g.Expect(rules[2].Match[i].Uri.GetPrefix()).To(Equal("/api/v1/"))
		g.Expect(rules[2].Match[i].Method.GetExact()).To(Equal(method))
	}

	// A route without methods denies all methods (no method match).
	g.Expect(rules[3].Match).To(HaveLen(1))
	g.Expect(rules[3].Match[0].Uri.GetPrefix()).To(Equal("/admin/"))
	g.Expect(rules[3].Match[0].Method).To(BeNil())
}

func TestBuildIstioGatewayDenyRulesEmpty(t *testing.T) {
	g := NewWithT(t)
	g.Expect(buildIstioGatewayDenyRules(nil, nil)).To(BeNil())
}

func TestPrependIstioGatewayDenyRules(t *testing.T) {
	g := NewWithT(t)

	catchAll := &istionetv1alpha3.HTTPRoute{
		Match: []*istionetv1alpha3.HTTPMatchRequest{
			{Uri: &istionetv1alpha3.StringMatch{MatchType: &istionetv1alpha3.StringMatch_Prefix{Prefix: "/"}}},
		},
	}
	vs := &istioclientnetv1.VirtualService{
		Spec: istionetv1alpha3.VirtualService{Http: []*istionetv1alpha3.HTTPRoute{catchAll}},
	}

	prependIstioGatewayDenyRules(vs,
		[]string{"/debug/"},
		[]configuration.DeniedRoute{{Path: "/api/v1/", Methods: []string{"POST"}}},
	)

	// Istio evaluates routes in order, so the deny rules must precede the catch-all route to ever match.
	g.Expect(vs.Spec.Http).To(HaveLen(3))
	g.Expect(vs.Spec.Http[0].DirectResponse.GetStatus()).To(Equal(uint32(403)))
	g.Expect(vs.Spec.Http[1].DirectResponse.GetStatus()).To(Equal(uint32(403)))
	g.Expect(vs.Spec.Http[2]).To(BeIdenticalTo(catchAll))
}

func TestPrependIstioGatewayDenyRulesNone(t *testing.T) {
	g := NewWithT(t)

	catchAll := &istionetv1alpha3.HTTPRoute{}
	vs := &istioclientnetv1.VirtualService{
		Spec: istionetv1alpha3.VirtualService{Http: []*istionetv1alpha3.HTTPRoute{catchAll}},
	}

	prependIstioGatewayDenyRules(vs, nil, nil)

	g.Expect(vs.Spec.Http).To(Equal([]*istionetv1alpha3.HTTPRoute{catchAll}))
}
