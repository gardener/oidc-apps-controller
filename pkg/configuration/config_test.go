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

package configuration

import (
	_ "embed"
	"os"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"
)

//go:embed test/configuration.yaml
var configYaml string

func TestTargetMatchLabels(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(configYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	target := getDeployment("test-02")
	extensionConfig.client = fake.NewClientBuilder().
		WithObjects(getTestNamespace()).
		WithObjects(target).
		WithObjects(getNginxDeployment()).
		Build()

	g.Expect(extensionConfig.Match(target)).To(BeTrue())
	g.Expect(extensionConfig.Match(getNginxDeployment())).To(BeFalse())
}

func TestTargetIngressHostPrefix(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(configYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	extensionConfig.client = fake.NewClientBuilder().
		WithObjects(getTestNamespace()).
		WithObjects(getDeployment("test-02")).
		Build()

	z := strings.SplitN(extensionConfig.GetHost(getDeployment("test-02")), ".", 2)
	g.Expect(len(z)).To(Equal(2))
	g.Expect(z[0]).To(HavePrefix("test-02-prefix-"))
	g.Expect(z[1]).To(Equal("domain.org"))
}

func TestTargetIngressHost(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(configYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	extensionConfig.client = fake.NewClientBuilder().
		WithObjects(getTestNamespace()).
		WithObjects(getDeployment("test-03")).
		Build()

	g.Expect(extensionConfig.GetHost(getDeployment("test-03"))).To(Equal("this.overwrites"))
}

func TestTargetWithoutIngressHost(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(configYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	extensionConfig.client = fake.NewClientBuilder().
		WithObjects(getTestNamespace()).
		WithObjects(getDeployment("test-04")).
		Build()

	g.Expect(extensionConfig.GetHost(getDeployment("test-04"))).To(Equal("test-04-test.domain.org"))
}

func TestTargetGlobalKubeSecret(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(configYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	extensionConfig.client = fake.NewClientBuilder().
		WithObjects(getTestNamespace()).
		WithObjects(getDeployment("test-03")).
		Build()

	g.Expect(extensionConfig.GetKubeSecretName(getDeployment("test-03"))).To(Equal("kubeconfig"))
}

func TestTargetKubeSecret(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(configYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	extensionConfig.client = fake.NewClientBuilder().
		WithObjects(getTestNamespace()).
		WithObjects(getDeployment("test-02")).
		Build()

	g.Expect(extensionConfig.GetKubeSecretName(getDeployment("test-02"))).To(Equal("target-kubeconfig"))
}

func TestTargetGlobalConfiguration(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(configYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	target := getDeployment("test-04")
	extensionConfig.client = fake.NewClientBuilder().
		WithObjects(getTestNamespace()).
		WithObjects(target).
		Build()

	g.Expect(extensionConfig.GetClientID(target)).To(Equal("client-id"))
	g.Expect(extensionConfig.GetScope(target)).To(Equal("openid email"))
	g.Expect(extensionConfig.GetClientSecret(target)).To(Equal("client-secret"))
	g.Expect(extensionConfig.GetRedirectURL(target)).To(Equal("https://test-04-test.domain.org/oauth2/callback"))
	g.Expect(extensionConfig.GetOidcIssuerURL(target)).To(Equal("https://oidc-provider.org"))
	g.Expect(extensionConfig.GetSslInsecureSkipVerify(target)).To(BeFalse())
	g.Expect(extensionConfig.GetInsecureOidcSkipIssuerVerification(target)).To(BeFalse())
	g.Expect(extensionConfig.GetInsecureOidcSkipNonce(target)).To(BeFalse())
	g.Expect(extensionConfig.GetKubeConfigStr(target)).To(Equal("Imt1YmVjb25maWci"))
	g.Expect(extensionConfig.GetKubeSecretName(target)).To(Equal("kubeconfig"))
}

func TestTargetConfiguration(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(configYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	target := getDeployment("test-02")
	extensionConfig.client = fake.NewClientBuilder().
		WithObjects(getTestNamespace()).
		WithObjects(target).
		Build()

	g.Expect(extensionConfig.GetClientID(target)).To(Equal("client-id-target"))
	g.Expect(extensionConfig.GetScope(target)).To(Equal("openid email target"))
	g.Expect(extensionConfig.GetClientSecret(target)).To(Equal("client-secret-target"))
	g.Expect(extensionConfig.GetRedirectURL(target)).To(Equal("https://app.org/oauth2/callback"))
	g.Expect(extensionConfig.GetOidcIssuerURL(target)).To(Equal("https://oidc-provider-target.org"))
	g.Expect(extensionConfig.GetOidcCASecretName(target)).To(Equal("target-oidc-ca"))
	g.Expect(extensionConfig.GetSslInsecureSkipVerify(target)).To(BeTrue())
	g.Expect(extensionConfig.GetInsecureOidcSkipIssuerVerification(target)).To(BeTrue())
	g.Expect(extensionConfig.GetInsecureOidcSkipNonce(target)).To(BeTrue())
	g.Expect(extensionConfig.GetKubeConfigStr(target)).To(Equal("a3ViZWNvbmZpZy10YXJnZXQK"))
	g.Expect(extensionConfig.GetKubeSecretName(target)).To(Equal("target-kubeconfig"))
}

func TestGardenConfig(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(configYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	target := getDeployment("test-02")
	extensionConfig.client = fake.NewClientBuilder().
		WithObjects(getTestNamespace()).
		WithObjects(target).
		Build()

	err = os.Setenv("GARDEN_SEED_DOMAIN_NAME", "seed.domain.org")
	g.Expect(err).ShouldNot(HaveOccurred())

	err = os.Setenv("GARDEN_SEED_OAUTH2_PROXY_CLIENT_ID", "seed-client-id")
	g.Expect(err).ShouldNot(HaveOccurred())

	host := extensionConfig.GetHost(target)
	g.Expect(host).To(Equal("test-02-prefix-4396f8.seed.domain.org"))

	clientID := extensionConfig.GetClientID(target)
	g.Expect(clientID).To(Equal("seed-client-id"))
}

func getDeployment(name string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "test",
			Labels:    map[string]string{"app.kubernetes.io/name": name},
		},
	}
}

func getNginxDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
			Labels:    map[string]string{"app.kubernetes.io/name": "nginx"},
		},
	}
}

func getTestNamespace() *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test",
			Labels: map[string]string{"kubernetes.io/metadata.name": "test"},
		},
	}
}
