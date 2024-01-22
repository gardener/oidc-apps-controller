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
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	if err := yaml.Unmarshal([]byte(configYaml01), &parsedConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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
	if !reflect.DeepEqual(parsedConfig, expectedConf) {
		t.Errorf("Expected %#v,\n got %#v", expectedConf, parsedConfig)
	}

}

//go:embed test/01-full-configuration.yaml
var configYaml string

func TestLoadFullConfiguration(t *testing.T) {

	parsedConfig := OIDCAppsControllerConfig{}
	if err := yaml.Unmarshal([]byte(configYaml), &parsedConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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

	if !reflect.DeepEqual(parsedConfig, expectedConf) {
		t.Errorf("Expected %#v,\n got %#v", expectedConf, parsedConfig)
	}

}

func TestContainsLabels(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	if err := yaml.Unmarshal([]byte(configYaml), &extensionConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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
				if !extensionConfig.Match(o) {
					t.Errorf("expected matching labels")
					t.Fail()
				}
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
				if extensionConfig.Match(o) {
					t.Errorf("expected no-matching labels")
					t.Fail()
				}
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
	if err := yaml.Unmarshal([]byte(targetHostYaml), &extensionConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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

	if extensionConfig.GetHost(deployment) != "my-service.domain.org" {
		t.Error("getting target host is not as expected",
			"expected: ", "my-service.domain.org",
			"got", extensionConfig.GetHost(deployment))
	}
}

//go:embed test/02-target-host-with-ingress-host.yaml
var targetHostWithIngressHostYaml string

func TestGetTargetHostWithIngressHost(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	if err := yaml.Unmarshal([]byte(targetHostWithIngressHostYaml), &extensionConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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

	if extensionConfig.GetHost(deployment) != "this.overwrites" {
		t.Error("getting target host is not as expected",
			"expected: ", "this.overwrites",
			"got",
			extensionConfig.GetHost(deployment))
	}
}

//go:embed test/02-target-host-without-prefix.yaml
var targetHostWithoutPrefix string

func TestGetTargetHostWithoutPrefix(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	if err := yaml.Unmarshal([]byte(targetHostWithoutPrefix), &extensionConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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

	if extensionConfig.GetHost(deployment) != "app-default.domain.org" {
		t.Error("getting target host is not as expected: ",
			"expected", "service.domain.org",
			"got", extensionConfig.GetHost(deployment))
	}
}

//go:embed test/03-with-kubesecretref.yaml
var withKubeSecretRef string

func TestGetWithKubeSecret(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	if err := yaml.Unmarshal([]byte(withKubeSecretRef), &extensionConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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

	if extensionConfig.GetKubeSecretName(deployment) != "kubeconfig-secret" {
		t.Error("getting kube secret name is not as expected:",
			"expected", "kubeconfig-secret",
			"got", extensionConfig.GetKubeSecretName(deployment))
	}
}

//go:embed test/03-with-target-kubesecretref.yaml
var withTargetKubeSecretRef string

func TestGetWithTargetKubeSecret(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	if err := yaml.Unmarshal([]byte(withTargetKubeSecretRef), &extensionConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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

	if extensionConfig.GetKubeSecretName(deployment) != "shall-have-precedence" {
		t.Error("getting kube secret name is not as expected: ",
			"expected", "shall-have-precedence",
			"got", extensionConfig.GetHost(deployment))
	}
}

//go:embed test/04-oidc-config.yaml
var oidcConfig string

func TestGetOidcConfig(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	if err := yaml.Unmarshal([]byte(oidcConfig), &extensionConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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

	if extensionConfig.GetClientID(deployment) != "client-id" {
		t.Error("getting clientId is not as expected: ",
			"expected", "client-id",
			"got", extensionConfig.GetClientID(deployment))
	}

	if extensionConfig.GetScope(deployment) != "openid email" {
		t.Error("getting scope is not as expected: ",
			"expected", "openid email",
			"got", extensionConfig.GetScope(deployment))
	}

	if extensionConfig.GetClientSecret(deployment) != "client-secret" {
		t.Error("getting clientSecret is not as expected: ",
			"expected", "client-secret",
			"got", extensionConfig.GetClientSecret(deployment))
	}

	if extensionConfig.GetRedirectUrl(deployment) != "https://service-default/oauth2/callback" {
		t.Error("getting redirectUrl is not as expected: ",
			"expected", "https://service-default/oauth2/callback",
			"got", extensionConfig.GetRedirectUrl(deployment))
	}

	if extensionConfig.GetOidcIssuerUrl(deployment) != "https://oidc.provider.org" {
		t.Error("getting oidcIssuerUrl is not as expected: ",
			"expected", "https://oidc.provider.org",
			"got", extensionConfig.GetOidcIssuerUrl(deployment))
	}

	if extensionConfig.GetSslInsecureSkipVerify(deployment) {
		t.Error("getting sslInsecureSkipVerify is not as expected: ",
			"expected", "false",
			"got", extensionConfig.GetSslInsecureSkipVerify(deployment))
	}
	if extensionConfig.GetInsecureOidcSkipIssuerVerification(deployment) {
		t.Error("getting insecureOidcSkipIssuerVerification is not as expected: ",
			"expected", "false",
			"got", extensionConfig.GetInsecureOidcSkipIssuerVerification(deployment))
	}

}

//go:embed test/04-oidc-target-config.yaml
var oidcTargetConfig string

func TestGetTargetOidcConfig(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}
	if err := yaml.Unmarshal([]byte(oidcTargetConfig), &extensionConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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

	if extensionConfig.GetClientID(deployment) != "client-id-target" {
		t.Error("getting clientId is not as expected: ",
			"expected", "client-id-target",
			"got", extensionConfig.GetClientID(deployment))
	}

	if extensionConfig.GetScope(deployment) != "openid email target" {
		t.Error("getting scope is not as expected: ",
			"expected", "openid email target",
			"got", extensionConfig.GetScope(deployment))
	}

	if extensionConfig.GetClientSecret(deployment) != "client-secret-target" {
		t.Error("getting clientSecret is not as expected: ",
			"expected", "client-secret-target",
			"got", extensionConfig.GetClientSecret(deployment))
	}

	if extensionConfig.GetRedirectUrl(deployment) != "https://target.domainName/oauth2/callback" {
		t.Error("getting redirectUrl is not as expected: ",
			"expected", "https://target.domainName/oauth2/callback",
			"got", extensionConfig.GetRedirectUrl(deployment))
	}

	if extensionConfig.GetOidcIssuerUrl(deployment) != "https://oidc.provider.org/target" {
		t.Error("getting oidcIssuerUrl is not as expected: ",
			"expected", "https://oidc.provider.org/target",
			"got", extensionConfig.GetOidcIssuerUrl(deployment))
	}

	if !extensionConfig.GetSslInsecureSkipVerify(deployment) {
		t.Error("getting sslInsecureSkipVerify is not as expected: ",
			"expected", "true",
			"got", extensionConfig.GetSslInsecureSkipVerify(deployment))
	}
	if !extensionConfig.GetInsecureOidcSkipIssuerVerification(deployment) {
		t.Error("getting insecureOidcSkipIssuerVerification is not as expected: ",
			"expected", "true",
			"got", extensionConfig.GetInsecureOidcSkipIssuerVerification(deployment))
	}
}

//go:embed test/05-kube-rbac-proxy-config.yaml
var kubeRbacProxyConfig string

func TestKubeRbacProxyConfig(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	if err := yaml.Unmarshal([]byte(kubeRbacProxyConfig), &extensionConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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

	if extensionConfig.GetKubeConfigStr(deployment) != "Imt1YmVjb25maWci" {
		t.Error("getting kube config string is not as expected: ",
			"expected", "Imt1YmVjb25maWci",
			"got", extensionConfig.GetKubeConfigStr(deployment))
	}
	if extensionConfig.GetKubeSecretName(deployment) != "kubeconfig-secret" {
		t.Error("getting kube config secret name is not as expected: ",
			"expected", "kubeconfig-secret",
			"got", extensionConfig.GetKubeSecretName(deployment))
	}

	if extensionConfig.GetOidcCABundle(deployment) != "...\n" {
		t.Error("getting oidc ca bundle is not as expected: ",
			"expected", "...\n",
			"got", extensionConfig.GetOidcCABundle(deployment))
	}

	if extensionConfig.GetOidcCASecretName(deployment) != "oidcca" {
		t.Error("getting oidc ca bundle secret name is not as expected: ",
			"expected", "oidcca",
			"got", extensionConfig.GetOidcCASecretName(deployment))
	}

}

//go:embed test/05-kube-rbac-proxy-target-config.yaml
var kubeRbacProxyTargetConfig string

func TestKubeRbacProxyTargetConfig(t *testing.T) {
	extensionConfig := OIDCAppsControllerConfig{}
	if err := yaml.Unmarshal([]byte(kubeRbacProxyTargetConfig), &extensionConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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

	if extensionConfig.GetKubeConfigStr(deployment) != "bXktb3RoZXIta3ViZS1jb25maWcK" {
		t.Error("getting kube config string is not as expected: ",
			"expected", "bXktb3RoZXIta3ViZS1jb25maWcK",
			"got", extensionConfig.GetKubeConfigStr(deployment))
	}

	if extensionConfig.GetKubeSecretName(deployment) != "kubeconfig-secret-target" {
		t.Error("getting kube config secret name is not as expected: ",
			"expected", "kubeconfig-secret-target",
			"got", extensionConfig.GetKubeSecretName(deployment))
	}

	if extensionConfig.GetOidcCABundle(deployment) != "...\n...\n" {
		t.Error("getting oidc ca bundle is not as expected: ",
			"expected", "...\n...\n",
			"got", extensionConfig.GetOidcCABundle(deployment))
	}

	if extensionConfig.GetOidcCASecretName(deployment) != "oidc-ca-target" {
		t.Error("getting oidc ca bundle secret name is not as expected: ",
			"expected", "oidcca",
			"got", extensionConfig.GetOidcCASecretName(deployment))
	}

}

//go:embed test/06-kubeconfig.yaml
var kubeRbacProxyKubeconfigConfig string

func TestKubeRbacProxyKubeConfig(t *testing.T) {

	extensionConfig := OIDCAppsControllerConfig{}

	if err := yaml.Unmarshal([]byte(kubeRbacProxyKubeconfigConfig), &extensionConfig); err != nil {
		t.Errorf("error unmarshalling configuration: %v", err)
	}

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
	if err != nil {
		t.Error(err)
	}

	kubeConfig := clientcmdv1.Config{}
	if err = yaml.Unmarshal(decodestr, &kubeConfig); err != nil {
		t.Error(err)
	}
	if _, err = yaml.Marshal(kubeConfig); err != nil {
		t.Error(err)
	}

}
