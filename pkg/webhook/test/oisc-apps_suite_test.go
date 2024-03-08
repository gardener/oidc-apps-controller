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

package test

import (
	_ "embed"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var tmpDir string

//go:embed configuration.yaml
var configFile string

var _log = zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true))

var _ = BeforeSuite(func() {
	tmpDir = GinkgoT().TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(configFile), 0444)
	Expect(err).NotTo(HaveOccurred())
	err = os.WriteFile(filepath.Join(tmpDir, "kubeconfig"), []byte("kubeconfig"), 0444)
	Expect(err).NotTo(HaveOccurred())
	err = os.WriteFile(filepath.Join(tmpDir, "token"), []byte("token"), 0444)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(os.RemoveAll, tmpDir)
})

func TestOidcApps(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OIDC Apps Webhook Suite")
}
