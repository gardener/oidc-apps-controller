// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package oidcappscontroller

import (
	"testing"

	. "github.com/onsi/gomega"
	"github.com/spf13/pflag"
)

func TestAddFlags(t *testing.T) {
	g := NewWithT(t)

	o := &Options{}
	flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
	o.AddFlags(flagSet)

	// Test parsing the flag
	err := flagSet.Parse([]string{"--config=test-config.yaml"})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(o.controllerConfigPath).To(Equal("test-config.yaml"))
}

func TestAddFlagsDefaults(t *testing.T) {
	g := NewWithT(t)

	o := &Options{}
	flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
	o.AddFlags(flagSet)

	// Parse with no arguments to get defaults
	err := flagSet.Parse([]string{})
	g.Expect(err).NotTo(HaveOccurred())

	// Check defaults are applied after parsing
	g.Expect(o.controllerConfigPath).To(Equal("extension-config.yaml"))
	g.Expect(o.useCertManager).To(BeFalse())
	g.Expect(o.webhookPort).To(Equal(10250))
	g.Expect(o.metricsPort).To(Equal(8080))
	g.Expect(o.webhookCertsDir).To(Equal("./certs"))
	g.Expect(o.webhookName).To(Equal("oidc-apps-controller"))
}
