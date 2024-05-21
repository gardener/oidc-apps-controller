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

package e2e

import (
	_ "embed"
	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"k8s.io/client-go/rest"
	"os"
	"path/filepath"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSute(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "E2E Suite")
}

//go:embed config.yaml
var configFile string
var (
	env  *envtest.Environment
	cfg  *rest.Config
	_log = zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true))
	err  error
)

var _ = BeforeSuite(func() {
	tmpDir := GinkgoT().TempDir()
	Expect(os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(configFile), 0444)).Should(Succeed())
	DeferCleanup(os.RemoveAll, tmpDir)

	// Setup oidc-apps-controller configuration
	configuration.CreateControllerConfigOrDie(filepath.Join(tmpDir, "config.yaml"))

	env = &envtest.Environment{}

	installWebHooks(env)
	cfg, err = env.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil(), "Failed to create a new test environment")
	
})

var _ = AfterSuite(func() {
	Expect(env.Stop()).Should(Succeed())
})
