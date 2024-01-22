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

package oidc_apps_controller

import "github.com/spf13/pflag"

// OidcAppsControllerOptions holds th controller starup parameters
type OidcAppsControllerOptions struct {
	webhookCertsDir      string
	controllerConfigPath string
	webhookName          string
	webhookPort          int
	registrySecret       string
	useCertManager       bool
}

// AddFlags adds the controller parameters to the flag set
func (o *OidcAppsControllerOptions) AddFlags(pflag *pflag.FlagSet) {
	pflag.StringVar(&o.controllerConfigPath, "config", "extension-config.yaml",
		"The file path to the extension configuration yaml.")
	pflag.StringVar(&o.registrySecret, "registry-secret", "",
		"The image pull secret for pull oidc-apps-controller container images")
	pflag.BoolVar(&o.useCertManager, "use-cert-manager", false,
		"Denotes if the webhook certificates are externally managed by a cert-manager.io instance or by this controller.")
	pflag.StringVar(&o.webhookCertsDir, "webhook-certs-dir", "./certs",
		"The directory containing webhook serving tls.key, tls.crt certificates")
	pflag.StringVar(&o.webhookName, "webhook-name", "oidc-apps-controller",
		"The name of the oidc-apps controller webhook ")
	pflag.IntVar(&o.webhookPort, "webhook-port", 10250,
		"The port of the oidc-apps controller webhook ")
}
