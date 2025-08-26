// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"flag"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/component-base/version"
	"k8s.io/component-base/version/verflag"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	oidcappscontroller "github.com/gardener/oidc-apps-controller/pkg/oidc-apps-controller"
)

var _log = logf.Log

// NewOidcAppsController returns the root command
func NewOidcAppsController() *cobra.Command {
	opts := &oidcappscontroller.Options{}
	fromFlags := &zap.Options{}

	cmd := &cobra.Command{
		Use:           "oidc-apps-controller",
		Short:         "This controller enhances target workloads with authentication & authorization proxies.",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logf.SetLogger(zap.New(zap.UseFlagOptions(fromFlags)))
			_log.Info("started",
				"version", version.Get().GitVersion,
				"revision", version.Get().GitCommit,
				"gitTreeState", version.Get().GitTreeState,
			)

			verflag.PrintAndExitIfRequested()

			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				_log.Info(fmt.Sprintf("FLAG: --%s=%s", flag.Name, flag.Value))
			})

			return oidcappscontroller.RunController(cmd.Context(), opts)
		},
	}

	verflag.AddFlags(cmd.Flags())
	opts.AddFlags(cmd.Flags())

	fs := flag.NewFlagSet("zap-logger", flag.ExitOnError)
	fromFlags.BindFlags(fs)
	cmd.Flags().AddGoFlagSet(fs)

	return cmd
}
