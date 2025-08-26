// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package oidcappscontroller

import "github.com/spf13/pflag"

// Options holds th controller starup parameters
type Options struct {
	useCertManager       bool
	webhookPort          int
	metricsPort          int
	controllerConfigPath string
	cacheSelectorString  string
	webhookCertsDir      string
	webhookName          string
	registrySecret       string
}

// AddFlags adds the controller parameters to the flag set
func (o *Options) AddFlags(flagSet *pflag.FlagSet) {
	flagSet.StringVar(&o.controllerConfigPath, "config", "extension-config.yaml",
		"The file path to the extension configuration yaml.")
	flagSet.StringVar(&o.registrySecret, "registry-secret", "",
		"The image pull secret for pull oidc-apps-controller container images")
	flagSet.BoolVar(&o.useCertManager, "use-cert-manager", false,
		"Denotes if the webhook certificates are externally managed by a cert-manager.io instance or by this controller.")
	flagSet.StringVar(&o.webhookCertsDir, "webhook-certs-dir", "./certs",
		"The directory containing webhook serving tls.key, tls.crt certificates")
	flagSet.StringVar(&o.webhookName, "webhook-name", "oidc-apps-controller",
		"The name of the oidc-apps controller webhook ")
	flagSet.IntVar(&o.webhookPort, "webhook-port", 10250,
		"The port of the oidc-apps controller webhook ")
	flagSet.IntVar(&o.metricsPort, "metrics-port", 8080,
		"The port of the oidc-apps controller metrics endpoint ")
	flagSet.StringVar(&o.cacheSelectorString, "cache-selector", "", "The selector string for controller-runtime cache.")
}
