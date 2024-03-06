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
	"encoding/base64"
	"os"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"
)

//go:embed test/01-simple-configuration.yaml
var configYaml01 string

func TestLoadSimpleConfiguration(t *testing.T) {

	parsedConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(configYaml01), &parsedConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	expectedConf := OIDCAppsControllerConfig{
		Configuration: Configuration{
			DomainName: "domain.org",
			Oauth2Proxy: &Oauth2ProxyConfig{
				Scope:         "openid email",
				ClientId:      "client-id",
				ClientSecret:  "client-secret",
				RedirectURL:   "https://app.org/oauth2/callback",
				OidcIssuerURL: "https://oidc-provider.org",
			},
			KubeRbacProxy: &KubeRbacProxyConfig{
				KubeSecretRef: &corev1.SecretReference{
					Name: "kubeconfig",
				},
				OidcCASecretRef: &corev1.SecretReference{
					Name: "oidcca",
				},
			},
		},
		Targets: []Target{
			{
				Name:           "service",
				TargetPort:     intstr.FromInt32(8443),
				TargetProtocol: "https",
				Ingress: &IngressConf{
					Create: true,
				},
			},
		},
	}
	g.Expect(parsedConfig).To(Equal(expectedConf))

}

//go:embed test/01-full-configuration.yaml
var configYaml string

func TestLoadFullConfiguration(t *testing.T) {
	g := NewWithT(t)
	parsedConfig := OIDCAppsControllerConfig{}
	err := yaml.Unmarshal([]byte(configYaml), &parsedConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	expectedConf := OIDCAppsControllerConfig{
		Configuration: Configuration{
			DomainName: "domain.org",
			Oauth2Proxy: &Oauth2ProxyConfig{
				Scope:         "openid email",
				ClientId:      "client-id",
				ClientSecret:  "client-secret",
				RedirectURL:   "https://app.org/oauth2/callback",
				OidcIssuerURL: "https://oidc-provider.org",
			},
			KubeRbacProxy: &KubeRbacProxyConfig{
				KubeSecretRef: &corev1.SecretReference{
					Name: "kubeconfig",
				},
				KubeConfigStr: "...\n",
				OidcCASecretRef: &corev1.SecretReference{
					Name: "oidcca",
				},
			},
		},
		Targets: []Target{
			{
				Name: "service",
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "test-01"},
				},
				LabelSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "app.kubernetes.io/name",
							Operator: "In",
							Values:   []string{"service"},
						},
					},
				},
				TargetPort:     intstr.FromInt32(8443),
				TargetProtocol: "https",
				Ingress: &IngressConf{
					Create:     true,
					HostPrefix: "service",
					TLSSecretRef: corev1.SecretReference{
						Name: "ingress-tls",
					},
				},
				Configuration: &Configuration{
					Oauth2Proxy: &Oauth2ProxyConfig{
						Scope:         "openid email",
						ClientId:      "target-client-id",
						ClientSecret:  "target-client-secret",
						RedirectURL:   "https://app.org/oauth2/callback",
						OidcIssuerURL: "https://oidc-provider.org",
					},
					KubeRbacProxy: &KubeRbacProxyConfig{
						KubeSecretRef: &corev1.SecretReference{
							Name: "target-kubeconfig",
						},

						OidcCASecretRef: &corev1.SecretReference{
							Name: "target-oidc-ca",
						},
						OidcCABundle: "...\n",
					},
				},
			},
		},
	}
	g.Expect(parsedConfig).To(Equal(expectedConf))

}

func TestContainsLabels(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(configYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-01",
			Labels: map[string]string{"kubernetes.io/metadata.name": "test-01"},
		},
	})
	extensionConfig.client = builder.Build()

	testTable := []struct {
		name string
		obj  client.Object
		test func(object client.Object)
	}{
		{
			name: "simple-match",
			obj: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "test-01",
					Labels:    map[string]string{"app.kubernetes.io/name": "service"},
				},
			},
			test: func(o client.Object) {
				g.Expect(extensionConfig.Match(o)).To(BeTrue())
			},
		},
		{
			name: "no-match",
			obj: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "default",
					Labels:    map[string]string{"app.kubernetes.io/name": "service"},
				},
			},
			test: func(o client.Object) {
				g.Expect(extensionConfig.Match(o)).To(BeFalse())
			},
		},
	}

	for _, table := range testTable {
		tb := table
		t.Run(tb.name, func(t *testing.T) {
			tb.test(tb.obj)
		})
	}

}

//go:embed test/02-target-host.yaml
var targetHostYaml string

func TestGetTargetHost(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(targetHostYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	})
	extensionConfig.client = builder.Build()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
		},
	}

	z := strings.SplitN(extensionConfig.GetHost(deployment), ".", 2)
	g.Expect(len(z)).To(Equal(2))
	g.Expect(z[0]).To(HavePrefix("my-service-"))
	g.Expect(z[1]).To(Equal("domain.org"))

}

//go:embed test/02-target-host-with-ingress-host.yaml
var targetHostWithIngressHostYaml string

func TestGetTargetHostWithIngressHost(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(targetHostWithIngressHostYaml), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	})
	extensionConfig.client = builder.Build()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
		},
	}
	g.Expect(extensionConfig.GetHost(deployment)).To(Equal("this.overwrites"))
}

//go:embed test/02-target-host-without-prefix.yaml
var targetHostWithoutPrefix string

func TestGetTargetHostWithoutPrefix(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(targetHostWithoutPrefix), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	})
	extensionConfig.client = builder.Build()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "default",
			Labels:    map[string]string{"app": "service"},
		},
	}

	g.Expect(extensionConfig.GetHost(deployment)).To(Equal("app-default.domain.org"))
}

//go:embed test/03-with-kubesecretref.yaml
var withKubeSecretRef string

func TestGetWithKubeSecret(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(withKubeSecretRef), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	})
	extensionConfig.client = builder.Build()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "default",
			Labels:    map[string]string{"app": "service"},
		},
	}

	g.Expect(extensionConfig.GetKubeSecretName(deployment)).To(Equal("kubeconfig-secret"))

}

//go:embed test/03-with-target-kubesecretref.yaml
var withTargetKubeSecretRef string

func TestGetWithTargetKubeSecret(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(withTargetKubeSecretRef), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	})
	extensionConfig.client = builder.Build()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
			Labels:    map[string]string{"app": "service"},
		},
	}

	g.Expect(extensionConfig.GetKubeSecretName(deployment)).To(Equal("shall-have-precedence"))
}

//go:embed test/04-oidc-config.yaml
var oidcConfig string

func TestGetOidcConfig(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(oidcConfig), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	})
	extensionConfig.client = builder.Build()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
			Labels:    map[string]string{"app": "service"},
		},
	}

	g.Expect(extensionConfig.GetClientID(deployment)).To(Equal("client-id"))
	g.Expect(extensionConfig.GetScope(deployment)).To(Equal("openid email"))
	g.Expect(extensionConfig.GetClientSecret(deployment)).To(Equal("client-secret"))
	g.Expect(extensionConfig.GetRedirectUrl(deployment)).To(Equal("https://service-default/oauth2/callback"))
	g.Expect(extensionConfig.GetOidcIssuerUrl(deployment)).To(Equal("https://oidc.provider.org"))
	g.Expect(extensionConfig.GetSslInsecureSkipVerify(deployment)).To(BeFalse())
	g.Expect(extensionConfig.GetInsecureOidcSkipIssuerVerification(deployment)).To(BeFalse())
	g.Expect(extensionConfig.GetInsecureOidcSkipNonce(deployment)).To(BeFalse())

}

//go:embed test/04-oidc-target-config.yaml
var oidcTargetConfig string

func TestGetTargetOidcConfig(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(oidcTargetConfig), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	})
	extensionConfig.client = builder.Build()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
			Labels:    map[string]string{"app": "service"},
		},
	}

	g.Expect(extensionConfig.GetClientID(deployment)).To(Equal("client-id-target"))
	g.Expect(extensionConfig.GetScope(deployment)).To(Equal("openid email target"))
	g.Expect(extensionConfig.GetClientSecret(deployment)).To(Equal("client-secret-target"))
	g.Expect(extensionConfig.GetRedirectUrl(deployment)).To(Equal("https://target.domainName/oauth2/callback"))
	g.Expect(extensionConfig.GetOidcIssuerUrl(deployment)).To(Equal("https://oidc.provider.org/target"))
	g.Expect(extensionConfig.GetSslInsecureSkipVerify(deployment)).To(BeTrue())
	g.Expect(extensionConfig.GetInsecureOidcSkipIssuerVerification(deployment)).To(BeTrue())
	g.Expect(extensionConfig.GetInsecureOidcSkipNonce(deployment)).To(BeFalse())
}

//go:embed test/05-kube-rbac-proxy-config.yaml
var kubeRbacProxyConfig string

func TestKubeRbacProxyConfig(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(kubeRbacProxyConfig), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	})
	extensionConfig.client = builder.Build()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
			Labels:    map[string]string{"app": "service"},
		},
	}

	g.Expect(extensionConfig.GetKubeConfigStr(deployment)).To(Equal("Imt1YmVjb25maWci"))
	g.Expect(extensionConfig.GetKubeSecretName(deployment)).To(Equal("kubeconfig-secret"))
	g.Expect(extensionConfig.GetOidcCABundle(deployment)).To(Equal("...\n"))
	g.Expect(extensionConfig.GetOidcCASecretName(deployment)).To(Equal("oidcca"))

}

//go:embed test/05-kube-rbac-proxy-target-config.yaml
var kubeRbacProxyTargetConfig string

func TestKubeRbacProxyTargetConfig(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(kubeRbacProxyTargetConfig), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	})
	extensionConfig.client = builder.Build()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
			Labels:    map[string]string{"app": "service"},
		},
	}

	g.Expect(extensionConfig.GetKubeConfigStr(deployment)).To(Equal("bXktb3RoZXIta3ViZS1jb25maWcK"))
	g.Expect(extensionConfig.GetKubeSecretName(deployment)).To(Equal("kubeconfig-secret-target"))
	g.Expect(extensionConfig.GetOidcCABundle(deployment)).To(Equal("...\n...\n"))
	g.Expect(extensionConfig.GetOidcCASecretName(deployment)).To(Equal("oidc-ca-target"))

}

//go:embed test/06-kubeconfig.yaml
var kubeRbacProxyKubeconfigConfig string

func TestKubeRbacProxyKubeConfig(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(kubeRbacProxyKubeconfigConfig), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	})
	extensionConfig.client = builder.Build()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
			Labels:    map[string]string{"app": "service"},
		},
	}

	str := extensionConfig.GetKubeConfigStr(deployment)
	decodestr, err := base64.StdEncoding.DecodeString(str)
	g.Expect(err).ShouldNot(HaveOccurred())

	kubeConfig := clientcmdv1.Config{}
	err = yaml.Unmarshal(decodestr, &kubeConfig)
	g.Expect(err).ShouldNot(HaveOccurred())
	g.Expect(yaml.Marshal(kubeConfig)).Error().ShouldNot(HaveOccurred())

}

//go:embed test/07-garden-extension-config.yaml
var gardenConfig string

func TestGardenConfig(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(gardenConfig), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	err = os.Setenv("GARDEN_SEED_DOMAIN_NAME", "seed.domain.org")
	g.Expect(err).ShouldNot(HaveOccurred())

	err = os.Setenv("GARDEN_SEED_OAUTH2_PROXY_CLIENT_ID", "seed-client-id")
	g.Expect(err).ShouldNot(HaveOccurred())

	// Create a fake client
	builder := fake.NewClientBuilder()
	builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	})
	extensionConfig.client = builder.Build()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
			Labels:    map[string]string{"app": "service"},
		},
	}

	host := extensionConfig.GetHost(deployment)
	g.Expect(host).To(Equal("service-default.seed.domain.org"))

	clientId := extensionConfig.GetClientID(deployment)
	g.Expect(clientId).To(Equal("seed-client-id"))

}

func TestLabelSelectors(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	g := NewWithT(t)
	err := yaml.Unmarshal([]byte(targetHostWithoutPrefix), &extensionConfig)
	g.Expect(err).ShouldNot(HaveOccurred())

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
			Labels:    map[string]string{"app": "service"},
		},
	}
	builder := fake.NewClientBuilder()
	extensionConfig.client = builder.WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
		},
	}).WithObjects(deployment).Build()

	selector, err := metav1.LabelSelectorAsSelector(extensionConfig.GetTargetLabelSelector(deployment))
	g.Expect(err).ShouldNot(HaveOccurred())
	g.Expect(selector.Matches(labels.Set(map[string]string{"app": "service"}))).To(BeTrue())

}
