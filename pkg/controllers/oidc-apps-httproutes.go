// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"fmt"
	"maps"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/randutils"
)

func createHTTPRouteForDeployment(object client.Object) (gatewayv1.HTTPRoute, error) {
	suffix := randutils.GenerateSha256(object.GetName() + "-" + object.GetNamespace())
	host := configuration.GetOIDCAppsControllerConfig().GetHTTPRouteHost(object)
	parentRefs := configuration.GetOIDCAppsControllerConfig().GetHTTPRouteParentRefs(object)

	httpRoute := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.HTTPRouteName + "-" + suffix,
			Namespace: object.GetNamespace(),
			Labels: map[string]string{
				constants.LabelKey: constants.LabelValue,
			},
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: convertParentRefs(parentRefs, object.GetNamespace()),
			},
			Hostnames: []gatewayv1.Hostname{gatewayv1.Hostname(host)},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Matches: []gatewayv1.HTTPRouteMatch{
						{
							Path: &gatewayv1.HTTPPathMatch{
								Type:  ptr.To(gatewayv1.PathMatchPathPrefix),
								Value: new("/"),
							},
						},
					},
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName(constants.ServiceNameOauth2Service + "-" + suffix),
									Port: ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}

	if annotations := configuration.GetOIDCAppsControllerConfig().GetHTTPRouteAnnotations(object); len(annotations) > 0 {
		httpRoute.Annotations = annotations
	}

	applyHTTPRouteDefaultPathRedirect(&httpRoute, object)

	extraLabels := configuration.GetOIDCAppsControllerConfig().GetHTTPRouteLabels(object)
	maps.Copy(httpRoute.Labels, extraLabels)

	return httpRoute, nil
}

func createHTTPRouteForStatefulSetPod(pod *corev1.Pod, object client.Object) (gatewayv1.HTTPRoute, error) {
	suffix := randutils.GenerateSha256(pod.GetName() + "-" + pod.GetNamespace())
	parentRefs := configuration.GetOIDCAppsControllerConfig().GetHTTPRouteParentRefs(object)

	hostPrefix, ok := pod.GetAnnotations()[constants.AnnotationHostKey]
	if !ok {
		return gatewayv1.HTTPRoute{}, fmt.Errorf("host annotation not found in pod %s/%s", pod.GetNamespace(), pod.GetName())
	}

	host, domain, _ := strings.Cut(hostPrefix, ".")
	index := fetchStrIndexIfPresent(pod)
	podHost := fmt.Sprintf("%s-%s.%s", host, index, domain)

	httpRoute := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.HTTPRouteName + "-" + addOptionalIndex(index+"-") + suffix,
			Namespace: object.GetNamespace(),
			Labels: map[string]string{
				constants.LabelKey: constants.LabelValue,
			},
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: convertParentRefs(parentRefs, object.GetNamespace()),
			},
			Hostnames: []gatewayv1.Hostname{gatewayv1.Hostname(podHost)},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Matches: []gatewayv1.HTTPRouteMatch{
						{
							Path: &gatewayv1.HTTPPathMatch{
								Type:  ptr.To(gatewayv1.PathMatchPathPrefix),
								Value: new("/"),
							},
						},
					},
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName(constants.ServiceNameOauth2Service + "-" + addOptionalIndex(index+"-") + suffix),
									Port: ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}

	if annotations := configuration.GetOIDCAppsControllerConfig().GetHTTPRouteAnnotations(object); len(annotations) > 0 {
		httpRoute.Annotations = annotations
	}

	applyHTTPRouteDefaultPathRedirect(&httpRoute, object)

	extraLabels := configuration.GetOIDCAppsControllerConfig().GetHTTPRouteLabels(object)
	maps.Copy(httpRoute.Labels, extraLabels)

	return httpRoute, nil
}

func applyHTTPRouteDefaultPathRedirect(httpRoute *gatewayv1.HTTPRoute, object client.Object) {
	defaultPath := configuration.GetOIDCAppsControllerConfig().GetHTTPRouteDefaultPath(object)
	if defaultPath == "" {
		return
	}

	redirectRule := gatewayv1.HTTPRouteRule{
		Matches: []gatewayv1.HTTPRouteMatch{
			{
				Path: &gatewayv1.HTTPPathMatch{
					Type:  ptr.To(gatewayv1.PathMatchExact),
					Value: new("/"),
				},
			},
		},
		Filters: []gatewayv1.HTTPRouteFilter{
			{
				Type: gatewayv1.HTTPRouteFilterRequestRedirect,
				RequestRedirect: &gatewayv1.HTTPRequestRedirectFilter{
					Path: &gatewayv1.HTTPPathModifier{
						Type:            gatewayv1.FullPathHTTPPathModifier,
						ReplaceFullPath: new(defaultPath),
					},
					StatusCode: new(302),
				},
			},
		},
	}

	httpRoute.Spec.Rules = append([]gatewayv1.HTTPRouteRule{redirectRule}, httpRoute.Spec.Rules...)
}

// convertParentRefs converts configuration parent refs to Gateway API parent refs
func convertParentRefs(refs []configuration.HTTPRouteParentRef, _ string) []gatewayv1.ParentReference {
	if len(refs) == 0 {
		return nil
	}

	result := make([]gatewayv1.ParentReference, 0, len(refs))
	for _, ref := range refs {
		parentRef := gatewayv1.ParentReference{
			Name: gatewayv1.ObjectName(ref.Name),
		}

		if ref.Namespace != "" {
			ns := gatewayv1.Namespace(ref.Namespace)
			parentRef.Namespace = &ns
		}

		if ref.SectionName != "" {
			sn := gatewayv1.SectionName(ref.SectionName)
			parentRef.SectionName = &sn
		}

		result = append(result, parentRef)
	}

	return result
}
