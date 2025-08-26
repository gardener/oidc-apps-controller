// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

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
