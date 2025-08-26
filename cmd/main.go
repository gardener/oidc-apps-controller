// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	_ "go.uber.org/automaxprocs"
	runtimelog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"

	"github.com/gardener/oidc-apps-controller/cmd/app"
)

func main() {
	ctx := signals.SetupSignalHandler()
	if err := app.NewOidcAppsController().ExecuteContext(ctx); err != nil {
		runtimelog.Log.Error(err, "error executing the main command")
		os.Exit(1)
	}
}
