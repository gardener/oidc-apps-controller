// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
)

func TestConvertParentRefs(t *testing.T) {
	t.Run("Empty refs", func(t *testing.T) {
		result := convertParentRefs(nil, "default")
		assert.Nil(t, result)

		result = convertParentRefs([]configuration.HTTPRouteParentRef{}, "default")
		assert.Nil(t, result)
	})

	t.Run("Single ref with all fields", func(t *testing.T) {
		refs := []configuration.HTTPRouteParentRef{
			{
				Name:        "my-gateway",
				Namespace:   "gateway-system",
				SectionName: "https",
			},
		}

		result := convertParentRefs(refs, "default")

		assert.Len(t, result, 1)
		assert.Equal(t, gatewayv1.ObjectName("my-gateway"), result[0].Name)
		assert.NotNil(t, result[0].Namespace)
		assert.Equal(t, gatewayv1.Namespace("gateway-system"), *result[0].Namespace)
		assert.NotNil(t, result[0].SectionName)
		assert.Equal(t, gatewayv1.SectionName("https"), *result[0].SectionName)
	})

	t.Run("Single ref with only name", func(t *testing.T) {
		refs := []configuration.HTTPRouteParentRef{
			{
				Name: "simple-gateway",
			},
		}

		result := convertParentRefs(refs, "default")

		assert.Len(t, result, 1)
		assert.Equal(t, gatewayv1.ObjectName("simple-gateway"), result[0].Name)
		assert.Nil(t, result[0].Namespace)
		assert.Nil(t, result[0].SectionName)
	})

	t.Run("Multiple refs", func(t *testing.T) {
		refs := []configuration.HTTPRouteParentRef{
			{
				Name:      "gateway-1",
				Namespace: "ns-1",
			},
			{
				Name:        "gateway-2",
				SectionName: "http",
			},
		}

		result := convertParentRefs(refs, "default")

		assert.Len(t, result, 2)
		assert.Equal(t, gatewayv1.ObjectName("gateway-1"), result[0].Name)
		assert.Equal(t, gatewayv1.ObjectName("gateway-2"), result[1].Name)
	})
}

func TestHTTPRouteLabels(t *testing.T) {
	t.Run("HTTPRoute has correct labels", func(t *testing.T) {
		// Verify that the label key and value constants are correct
		assert.Equal(t, "oidc-application-controller/component", constants.LabelKey)
		assert.Equal(t, "oidc-apps", constants.LabelValue)
	})
}

func TestHTTPRouteNameConstant(t *testing.T) {
	t.Run("HTTPRoute name constant is correct", func(t *testing.T) {
		assert.Equal(t, "oauth2-httproute", constants.HTTPRouteName)
	})
}
