// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package oidcappscontroller

import (
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestGatewayAPISchemeInstallation(t *testing.T) {
	g := NewWithT(t)

	// Test that Gateway API scheme can be installed when CRDs are expected to be present
	sch := runtime.NewScheme()
	err := scheme.AddToScheme(sch)
	g.Expect(err).NotTo(HaveOccurred())

	// Verify Gateway API is not registered initially
	g.Expect(sch.IsGroupRegistered("gateway.networking.k8s.io")).To(BeFalse())

	// Install Gateway API scheme
	err = gatewayv1.Install(sch)
	g.Expect(err).NotTo(HaveOccurred())

	// Verify Gateway API is now registered
	g.Expect(sch.IsGroupRegistered("gateway.networking.k8s.io")).To(BeTrue())
}

func TestGatewayAPISchemeMissingScenario(t *testing.T) {
	g := NewWithT(t)

	// This test verifies the behavior when Gateway API types are NOT in the scheme.
	// This simulates the scenario when HTTPRoute support is disabled and CRDs are not present.
	sch := runtime.NewScheme()
	err := scheme.AddToScheme(sch)
	g.Expect(err).NotTo(HaveOccurred())

	// Gateway API should not be registered when we haven't installed it
	g.Expect(sch.IsGroupRegistered("gateway.networking.k8s.io")).To(BeFalse())

	// Attempting to create an HTTPRoute object without the scheme registered
	// would fail at runtime. This test documents that the controller only
	// registers the Gateway API scheme when global.httpRoutes.enabled is true.

	// When HTTPRoute support is disabled (default), the controller:
	// 1. Does not install Gateway API scheme
	// 2. Does not add HTTPRoute to cache
	// 3. Does not add HTTPRoute watches
	// This means missing Gateway API CRDs are handled gracefully by simply
	// not enabling the feature.
}

func TestHTTPRouteTypeRegistration(t *testing.T) {
	g := NewWithT(t)

	// Test that HTTPRoute type is properly registered after scheme installation
	sch := runtime.NewScheme()
	err := scheme.AddToScheme(sch)
	g.Expect(err).NotTo(HaveOccurred())

	err = gatewayv1.Install(sch)
	g.Expect(err).NotTo(HaveOccurred())

	// Verify HTTPRoute is a known type
	httpRoute := &gatewayv1.HTTPRoute{}
	gvks, _, err := sch.ObjectKinds(httpRoute)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(gvks).To(HaveLen(1))
	g.Expect(gvks[0].Group).To(Equal("gateway.networking.k8s.io"))
	g.Expect(gvks[0].Version).To(Equal("v1"))
	g.Expect(gvks[0].Kind).To(Equal("HTTPRoute"))
}
