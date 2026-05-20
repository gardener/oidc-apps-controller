// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"fmt"
	"maps"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	istionetv1alpha3 "istio.io/api/networking/v1alpha3"
	istioclientnetv1 "istio.io/client-go/pkg/apis/networking/v1"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/randutils"
)

// --- Gateway builders ---

func createIstioGatewayForDeployment(object client.Object) (*istioclientnetv1.Gateway, error) {
	suffix := randutils.GenerateSha256(object.GetName() + "-" + object.GetNamespace())
	host := configuration.GetOIDCAppsControllerConfig().GetIstioGatewayHost(object)

	gw := buildGateway(suffix, "", host, object)

	return gw, nil
}

func createIstioGatewayForStatefulSetPod(pod *corev1.Pod, object client.Object) (*istioclientnetv1.Gateway, error) {
	suffix := randutils.GenerateSha256(pod.GetName() + "-" + pod.GetNamespace())

	hostPrefix, ok := pod.GetAnnotations()[constants.AnnotationHostKey]
	if !ok {
		return nil, fmt.Errorf("host annotation not found in pod %s/%s", pod.GetNamespace(), pod.GetName())
	}

	host, domain, _ := strings.Cut(hostPrefix, ".")
	index := fetchStrIndexIfPresent(pod)
	podHost := fmt.Sprintf("%s-%s.%s", host, index, domain)

	gw := buildGateway(suffix, index, podHost, object)

	return gw, nil
}

func buildGateway(suffix, index, host string, object client.Object) *istioclientnetv1.Gateway {
	cfg := configuration.GetOIDCAppsControllerConfig()
	selector := cfg.GetIstioGatewaySelector()
	tlsSecretRef := cfg.GetIstioGatewayTLSSecretRef(object)

	server := &istionetv1alpha3.Server{
		Port: &istionetv1alpha3.Port{
			Number:   443,
			Name:     "https",
			Protocol: "HTTPS",
		},
		Hosts: []string{host},
	}

	if tlsSecretRef != "" {
		server.Tls = &istionetv1alpha3.ServerTLSSettings{
			Mode:           istionetv1alpha3.ServerTLSSettings_SIMPLE,
			CredentialName: tlsSecretRef,
		}
	}

	gw := &istioclientnetv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.IstioGatewayName + "-" + addOptionalIndex(index+"-") + suffix,
			Namespace: object.GetNamespace(),
			Labels: map[string]string{
				constants.LabelKey: constants.LabelValue,
			},
		},
		Spec: istionetv1alpha3.Gateway{
			Selector: selector,
			Servers:  []*istionetv1alpha3.Server{server},
		},
	}

	if annotations := cfg.GetIstioGatewayAnnotations(object); len(annotations) > 0 {
		gw.Annotations = annotations
	}

	extraLabels := cfg.GetIstioGatewayLabels(object)
	maps.Copy(gw.Labels, extraLabels)

	return gw
}

// IstioGatewayNameForDeployment returns the Gateway name for a given deployment target.
// Used by VirtualService builder to auto-reference the created Gateway.
func IstioGatewayNameForDeployment(object client.Object) string {
	suffix := randutils.GenerateSha256(object.GetName() + "-" + object.GetNamespace())
	return constants.IstioGatewayName + "-" + suffix
}

// IstioGatewayNameForStatefulSetPod returns the Gateway name for a given statefulset pod.
// Used by VirtualService builder to auto-reference the created Gateway.
func IstioGatewayNameForStatefulSetPod(pod *corev1.Pod) string {
	suffix := randutils.GenerateSha256(pod.GetName() + "-" + pod.GetNamespace())
	index := fetchStrIndexIfPresent(pod)
	return constants.IstioGatewayName + "-" + addOptionalIndex(index+"-") + suffix
}

func createIstioVirtualServiceForDeployment(object client.Object) (*istioclientnetv1.VirtualService, error) {
	suffix := randutils.GenerateSha256(object.GetName() + "-" + object.GetNamespace())
	host := configuration.GetOIDCAppsControllerConfig().GetIstioGatewayHost(object)
	gwName := IstioGatewayNameForDeployment(object)
	gateways := []string{gwName}

	vs := &istioclientnetv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.IstioVirtualServiceName + "-" + suffix,
			Namespace: object.GetNamespace(),
			Labels: map[string]string{
				constants.LabelKey: constants.LabelValue,
			},
		},
		Spec: istionetv1alpha3.VirtualService{
			Hosts:    []string{host},
			Gateways: gateways,
			ExportTo: []string{"*"},
			Http: []*istionetv1alpha3.HTTPRoute{
				{
					Match: []*istionetv1alpha3.HTTPMatchRequest{
						{
							Uri: &istionetv1alpha3.StringMatch{
								MatchType: &istionetv1alpha3.StringMatch_Prefix{
									Prefix: "/",
								},
							},
						},
					},
					Route: []*istionetv1alpha3.HTTPRouteDestination{
						{
							Destination: &istionetv1alpha3.Destination{
								Host: constants.ServiceNameOauth2Service + "-" + suffix + "." + object.GetNamespace() + ".svc.cluster.local",
								Port: &istionetv1alpha3.PortSelector{
									Number: 8080,
								},
							},
						},
					},
				},
			},
		},
	}

	if annotations := configuration.GetOIDCAppsControllerConfig().GetIstioGatewayAnnotations(object); len(annotations) > 0 {
		vs.Annotations = annotations
	}

	applyIstioGatewayDefaultPathRedirect(vs, object)
	applyIstioGatewayDeniedPaths(vs, object)

	extraLabels := configuration.GetOIDCAppsControllerConfig().GetIstioGatewayLabels(object)
	maps.Copy(vs.Labels, extraLabels)

	return vs, nil
}

func createIstioVirtualServiceForStatefulSetPod(pod *corev1.Pod, object client.Object) (*istioclientnetv1.VirtualService, error) {
	suffix := randutils.GenerateSha256(pod.GetName() + "-" + pod.GetNamespace())
	gwName := IstioGatewayNameForStatefulSetPod(pod)
	gateways := []string{gwName}

	hostPrefix, ok := pod.GetAnnotations()[constants.AnnotationHostKey]
	if !ok {
		return nil, fmt.Errorf("host annotation not found in pod %s/%s", pod.GetNamespace(), pod.GetName())
	}

	host, domain, _ := strings.Cut(hostPrefix, ".")
	index := fetchStrIndexIfPresent(pod)
	podHost := fmt.Sprintf("%s-%s.%s", host, index, domain)

	vs := &istioclientnetv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.IstioVirtualServiceName + "-" + addOptionalIndex(index+"-") + suffix,
			Namespace: object.GetNamespace(),
			Labels: map[string]string{
				constants.LabelKey: constants.LabelValue,
			},
		},
		Spec: istionetv1alpha3.VirtualService{
			Hosts:    []string{podHost},
			Gateways: gateways,
			ExportTo: []string{"*"},
			Http: []*istionetv1alpha3.HTTPRoute{
				{
					Match: []*istionetv1alpha3.HTTPMatchRequest{
						{
							Uri: &istionetv1alpha3.StringMatch{
								MatchType: &istionetv1alpha3.StringMatch_Prefix{
									Prefix: "/",
								},
							},
						},
					},
					Route: []*istionetv1alpha3.HTTPRouteDestination{
						{
							Destination: &istionetv1alpha3.Destination{
								Host: constants.ServiceNameOauth2Service + "-" + addOptionalIndex(index+"-") + suffix + "." + object.GetNamespace() + ".svc.cluster.local",
								Port: &istionetv1alpha3.PortSelector{
									Number: 8080,
								},
							},
						},
					},
				},
			},
		},
	}

	if annotations := configuration.GetOIDCAppsControllerConfig().GetIstioGatewayAnnotations(object); len(annotations) > 0 {
		vs.Annotations = annotations
	}

	applyIstioGatewayDefaultPathRedirect(vs, object)
	applyIstioGatewayDeniedPaths(vs, object)

	extraLabels := configuration.GetOIDCAppsControllerConfig().GetIstioGatewayLabels(object)
	maps.Copy(vs.Labels, extraLabels)

	return vs, nil
}

func applyIstioGatewayDefaultPathRedirect(vs *istioclientnetv1.VirtualService, object client.Object) {
	defaultPath := configuration.GetOIDCAppsControllerConfig().GetIstioGatewayDefaultPath(object)
	if defaultPath == "" {
		return
	}

	redirectRule := &istionetv1alpha3.HTTPRoute{
		Match: []*istionetv1alpha3.HTTPMatchRequest{
			{
				Uri: &istionetv1alpha3.StringMatch{
					MatchType: &istionetv1alpha3.StringMatch_Exact{
						Exact: "/",
					},
				},
			},
		},
		Redirect: &istionetv1alpha3.HTTPRedirect{
			Uri:          defaultPath,
			RedirectCode: 302,
		},
	}

	vs.Spec.Http = append([]*istionetv1alpha3.HTTPRoute{redirectRule}, vs.Spec.Http...)
}

func applyIstioGatewayDeniedPaths(vs *istioclientnetv1.VirtualService, object client.Object) {
	deniedPaths := configuration.GetOIDCAppsControllerConfig().GetIstioGatewayDeniedPaths(object)
	if len(deniedPaths) == 0 {
		return
	}

	denyRules := make([]*istionetv1alpha3.HTTPRoute, 0, len(deniedPaths))
	for _, path := range deniedPaths {
		denyRules = append(denyRules, &istionetv1alpha3.HTTPRoute{
			Match: []*istionetv1alpha3.HTTPMatchRequest{
				{
					Uri: &istionetv1alpha3.StringMatch{
						MatchType: &istionetv1alpha3.StringMatch_Prefix{
							Prefix: path,
						},
					},
				},
			},
			DirectResponse: &istionetv1alpha3.HTTPDirectResponse{
				Status: 403,
			},
		})
	}

	vs.Spec.Http = append(denyRules, vs.Spec.Http...)
}

func createIstioDestinationRuleForDeployment(object client.Object) *istioclientnetv1.DestinationRule {
	suffix := randutils.GenerateSha256(object.GetName() + "-" + object.GetNamespace())
	host := constants.ServiceNameOauth2Service + "-" + suffix + "." + object.GetNamespace() + ".svc.cluster.local"
	return buildDestinationRule(suffix, "", host, object)
}

func createIstioDestinationRuleForStatefulSetPod(pod *corev1.Pod, object client.Object) *istioclientnetv1.DestinationRule {
	suffix := randutils.GenerateSha256(pod.GetName() + "-" + pod.GetNamespace())
	index := fetchStrIndexIfPresent(pod)
	host := constants.ServiceNameOauth2Service + "-" + addOptionalIndex(index+"-") + suffix + "." + object.GetNamespace() + ".svc.cluster.local"
	return buildDestinationRule(suffix, index, host, object)
}

func buildDestinationRule(suffix, index, host string, object client.Object) *istioclientnetv1.DestinationRule {
	return &istioclientnetv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ServiceNameOauth2Service + "-" + addOptionalIndex(index+"-") + suffix,
			Namespace: object.GetNamespace(),
			Labels: map[string]string{
				constants.LabelKey: constants.LabelValue,
			},
		},
		Spec: istionetv1alpha3.DestinationRule{
			ExportTo: []string{"*"},
			Host:     host,
			TrafficPolicy: &istionetv1alpha3.TrafficPolicy{
				// explicitly default ClientTlsSettings mode to DISABLE (no TLS to from istio gateway
				// to oauth2-proxy). Otherwise, TLS is attempted and the proxy isn't configured
				// for that.
				Tls: &istionetv1alpha3.ClientTLSSettings{},
			},
		},
	}
}
