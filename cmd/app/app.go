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

package app

import (
	"flag"
	"fmt"

	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/oidc-apps-controller"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/component-base/version"
	"k8s.io/component-base/version/verflag"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var _log = logf.Log

// NewOidcAppsController returns the root command
func NewOidcAppsController() *cobra.Command {

	opts := &oidc_apps_controller.OidcAppsControllerOptions{}
	fromFlags := &zap.Options{}

	cmd := &cobra.Command{
		Use:           "oidc-apps-controller",
		Short:         "This controller enhances target workloads with authentication & authorization proxies.",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logf.SetLogger(zap.New(zap.UseFlagOptions(fromFlags)))

			verflag.PrintAndExitIfRequested()

			_log.Info(fmt.Sprintf("VERSION: %s", version.Get().String()))
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				_log.Info(fmt.Sprintf("FLAG: --%s=%s", flag.Name, flag.Value))
			})

			return oidc_apps_controller.RunController(cmd.Context(), opts)
		},
	}

	verflag.AddFlags(cmd.Flags())
	opts.AddFlags(cmd.Flags())

	fs := flag.NewFlagSet("zap-logger", flag.ExitOnError)
	fromFlags.BindFlags(fs)
	cmd.Flags().AddGoFlagSet(fs)

	return cmd
}
