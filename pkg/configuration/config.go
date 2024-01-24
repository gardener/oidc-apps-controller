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
	"context"
	"os"
	"strings"
	"sync"

	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/constants"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels2 "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/yaml"
)

// OIDCAppsControllerConfig is the root configuration node
type OIDCAppsControllerConfig struct {
	Configuration Configuration `json:"configuration"`
	Targets       []Target      `json:"targets"`
	client        client.Client
	log           logr.Logger
}

// Configuration holds the concrete target configurations for the auth & autz proxies
type Configuration struct {
	Oauth2Proxy   *Oauth2ProxyConfig   `json:"oauth2Proxy,omitempty"`
	KubeRbacProxy *KubeRbacProxyConfig `json:"kubeRbacProxy,omitempty"`

	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	DomainName  string            `json:"domainName,omitempty"`
}

// Oauth2ProxyConfig OIDC Provider configuration
type Oauth2ProxyConfig struct {
	Scope                              string `json:"scope,omitempty"`
	ClientId                           string `json:"clientId"`
	ClientSecret                       string `json:"clientSecret,omitempty"`
	RedirectURL                        string `json:"redirectUrl"`
	OidcIssuerURL                      string `json:"oidcIssuerUrl"`
	SSLInsecureSkipVerify              *bool  `json:"sslInsecureSkipVerify,omitempty"`
	InsecureOidcSkipIssuerVerification *bool  `json:"insecureOidcSkipIssuerVerification,omitempty"`
}

// KubeRbacProxyConfig kube-rbac-proxy configuration
type KubeRbacProxyConfig struct {
	KubeConfigStr   string                  `json:"kubeConfigStr,omitempty"`
	KubeSecretRef   *corev1.SecretReference `json:"kubeSecretRef,omitempty"`
	OidcCABundle    string                  `json:"oidcCABundle,omitempty"`
	OidcCASecretRef *corev1.SecretReference `json:"oidcCASecretRef,omitempty"`
}

// Target workload selector configuration
type Target struct {
	Name              string                `json:"name"`
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	LabelSelector     *metav1.LabelSelector `json:"labelSelector,omitempty"`
	TargetPort        intstr.IntOrString    `json:"targetPort,omitempty"`
	TargetProtocol    string                `json:"targetProtocol,omitempty"`
	Ingress           *IngressConf          `json:"ingress,omitempty"`
	Configuration     *Configuration        `json:"configuration,omitempty"`
}

// IngressConf holds configuration for the ingress entry-point
type IngressConf struct {
	Create           bool                   `json:"create,omitempty"`
	HostPrefix       string                 `json:"hostPrefix,omitempty"`
	Host             string                 `json:"host,omitempty"`
	Annotations      map[string]string      `json:"annotations,omitempty"`
	TLSSecretRef     corev1.SecretReference `json:"tlsSecretRef,omitempty"`
	IngressClassName string                 `json:"ingressClassName,omitempty"`
}

var config *OIDCAppsControllerConfig
var once sync.Once

// Options is an option setter function
type Options func(config *OIDCAppsControllerConfig)

// WithClient supports setting client.Client option
func WithClient(c client.Client) Options {
	return func(config *OIDCAppsControllerConfig) {
		config.client = c
	}
}

// WithLog supports setting default logger
func WithLog(l logr.Logger) Options {
	return func(config *OIDCAppsControllerConfig) {
		config.log = l
	}
}

// CreateControllerConfigOrDie initializes the targets configurations or exits the controller when unsuccessful
func CreateControllerConfigOrDie(path string, opts ...Options) *OIDCAppsControllerConfig {
	var (
		cf  []byte
		err error
	)

	once.Do(func() {
		config = &OIDCAppsControllerConfig{}
		for _, o := range opts {
			o(config)
		}

		if cf, err = os.ReadFile(path); err != nil {
			if config.log.IsZero() {
				log.SetLogger(zap.New(zap.UseDevMode(true)))
				config.log = log.Log.WithName("oidcAppsExtensionConfig")
			}
			config.log.Error(err, "failed to read extension configuration", "path", path)
			os.Exit(1)
		}

		if err = yaml.Unmarshal(cf, config); err != nil {
			if config.log.IsZero() {
				log.SetLogger(zap.New(zap.UseDevMode(true)))
				config.log = log.Log.WithName("oidcAppsExtensionConfig")
			}
			config.log.Error(err, "failed to unmarshal extension configuration")
			os.Exit(1)
		}

	})
	return config
}

// GetOIDCAppsControllerConfig returns the loaded configuration
func GetOIDCAppsControllerConfig() *OIDCAppsControllerConfig {
	return config
}

// Match accepts a client.Object and verifies if is a target defined in the controller configuration
func (c *OIDCAppsControllerConfig) Match(o client.Object) bool {

	for _, t := range c.Targets {
		if c.targetMatchesLabels(t, o) {
			return true
		}
	}
	return false
}

// GetHost return the domain name for a given workload target
func (c *OIDCAppsControllerConfig) GetHost(object client.Object) string {
	t := c.fetchTarget(object)

	domain := c.Configuration.DomainName
	prefix := object.GetName() + "-" + object.GetNamespace()
	if t.Ingress != nil && t.Ingress.HostPrefix != "" {
		prefix = t.Ingress.HostPrefix
	}
	if t.Ingress != nil && t.Ingress.Host != "" {
		prefix, domain, _ = strings.Cut(t.Ingress.Host, ".")
	}

	// If we run in gardener seed environment the domain name is not fetched from the configuration
	// but from the kube-apiserver ingress in the garden namespace
	// This is a workaround until we have a proper solution for the propagating seed specific configurations
	// for the extension controllers
	if domain == "" && (len(os.Getenv(oidc_apps_controller.GARDEN_DOMAIN_NAME)) > 0) {
		domain = os.Getenv(oidc_apps_controller.GARDEN_DOMAIN_NAME)
	}

	if domain == "" {
		return prefix
	}

	return strings.Join([]string{prefix, domain}, ".")

}

// GetUpstreamTarget returns the protocol and port tuple of the target workload
func (c *OIDCAppsControllerConfig) GetUpstreamTarget(object client.Object) string {
	t := c.fetchTarget(object)
	b := strings.Builder{}
	protocol := "http"
	if t.TargetProtocol == "https" {
		protocol = "https"
	}
	b.Grow(9)
	b.WriteString("protocol=")
	b.Grow(len(protocol))
	b.WriteString(protocol)
	b.Grow(7)
	b.WriteString(", port=")
	b.Grow(len(t.TargetPort.String()))
	b.WriteString(t.TargetPort.String())

	return b.String()
}

// GetKubeSecretName returns the kubeconfig secret name of the target workload
func (c *OIDCAppsControllerConfig) GetKubeSecretName(object client.Object) string {

	secretName := ""
	t := c.fetchTarget(object)
	if t.Configuration != nil &&
		t.Configuration.KubeRbacProxy != nil &&
		t.Configuration.KubeRbacProxy.KubeSecretRef != nil &&
		t.Configuration.KubeRbacProxy.KubeSecretRef.Name != "" {
		return t.Configuration.KubeRbacProxy.KubeSecretRef.Name
	}
	if c.Configuration.KubeRbacProxy != nil &&
		c.Configuration.KubeRbacProxy.KubeSecretRef != nil &&
		c.Configuration.KubeRbacProxy.KubeSecretRef.Name != "" {
		secretName = c.Configuration.KubeRbacProxy.KubeSecretRef.Name
	}

	return secretName
}

// GetKubeConfigStr returns the kubeconfig string of the target workload
func (c *OIDCAppsControllerConfig) GetKubeConfigStr(object client.Object) string {

	kubeConfig := ""
	t := c.fetchTarget(object)
	if t.Configuration != nil &&
		t.Configuration.KubeRbacProxy != nil &&
		t.Configuration.KubeRbacProxy.KubeConfigStr != "" {
		return t.Configuration.KubeRbacProxy.KubeConfigStr
	}
	if c.Configuration.KubeRbacProxy != nil &&
		c.Configuration.KubeRbacProxy.KubeConfigStr != "" {
		kubeConfig = c.Configuration.KubeRbacProxy.KubeConfigStr
	}

	return kubeConfig
}

// GetOidcCASecretName returns the secret name holding the trusts CA certificate of the OIDC Provider
func (c *OIDCAppsControllerConfig) GetOidcCASecretName(object client.Object) string {

	secretName := ""
	t := c.fetchTarget(object)
	if t.Configuration != nil &&
		t.Configuration.KubeRbacProxy != nil &&
		t.Configuration.KubeRbacProxy.OidcCASecretRef != nil &&
		t.Configuration.KubeRbacProxy.OidcCASecretRef.Name != "" {
		return t.Configuration.KubeRbacProxy.OidcCASecretRef.Name
	}
	if c.Configuration.KubeRbacProxy != nil &&
		c.Configuration.KubeRbacProxy.OidcCASecretRef != nil &&
		c.Configuration.KubeRbacProxy.OidcCASecretRef.Name != "" {
		secretName = c.Configuration.KubeRbacProxy.OidcCASecretRef.Name
	}

	return secretName
}

// GetOidcCABundle returns the trusted CA bundle certificates of the OIDC Provider
func (c *OIDCAppsControllerConfig) GetOidcCABundle(object client.Object) string {

	oidcCABundle := ""
	t := c.fetchTarget(object)
	if t.Configuration != nil &&
		t.Configuration.KubeRbacProxy != nil &&
		t.Configuration.KubeRbacProxy.OidcCABundle != "" {
		return t.Configuration.KubeRbacProxy.OidcCABundle
	}
	if c.Configuration.KubeRbacProxy != nil &&
		c.Configuration.KubeRbacProxy.OidcCABundle != "" {
		oidcCABundle = c.Configuration.KubeRbacProxy.OidcCABundle
	}

	return oidcCABundle
}

// GetClientID returns the OIDC Provider client_id for the given workload target
func (c *OIDCAppsControllerConfig) GetClientID(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Configuration != nil &&
		t.Configuration.Oauth2Proxy != nil &&
		t.Configuration.Oauth2Proxy.ClientId != "" {
		return t.Configuration.Oauth2Proxy.ClientId
	}

	if c.Configuration.Oauth2Proxy != nil &&
		c.Configuration.Oauth2Proxy.ClientId != "" {
		return c.Configuration.Oauth2Proxy.ClientId
	}
	return ""
}

// GetOidcIssuerURL returns the OIDC Provider URL for the given workload target
func (c *OIDCAppsControllerConfig) GetOidcIssuerURL(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Configuration != nil && t.Configuration.Oauth2Proxy != nil &&
		t.Configuration.Oauth2Proxy.OidcIssuerURL != "" {
		return t.Configuration.Oauth2Proxy.OidcIssuerURL
	}

	if c.Configuration.Oauth2Proxy != nil &&
		c.Configuration.Oauth2Proxy.OidcIssuerURL != "" {
		return c.Configuration.Oauth2Proxy.OidcIssuerURL
	}
	return ""
}

// GetClientSecret returns the OIDC Provider secret for the given target workload
func (c *OIDCAppsControllerConfig) GetClientSecret(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Configuration != nil &&
		t.Configuration.Oauth2Proxy != nil &&
		t.Configuration.Oauth2Proxy.ClientSecret != "" {
		return t.Configuration.Oauth2Proxy.ClientSecret
	}

	if c.Configuration.Oauth2Proxy != nil &&
		c.Configuration.Oauth2Proxy.ClientSecret != "" {
		return c.Configuration.Oauth2Proxy.ClientSecret
	}
	return ""
}

// GetScope returns the OIDC Provider scope for the given target workload
func (c *OIDCAppsControllerConfig) GetScope(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Configuration != nil && t.Configuration.Oauth2Proxy != nil &&
		t.Configuration.Oauth2Proxy.Scope != "" {
		return t.Configuration.Oauth2Proxy.Scope
	}

	if c.Configuration.Oauth2Proxy != nil &&
		c.Configuration.Oauth2Proxy.Scope != "" {
		return c.Configuration.Oauth2Proxy.Scope
	}
	return ""
}

// GetRedirectUrl returns the OIDC Provider redirect URL for the given workload target
func (c *OIDCAppsControllerConfig) GetRedirectUrl(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Configuration != nil && t.Configuration.Oauth2Proxy != nil &&
		t.Configuration.Oauth2Proxy.RedirectURL != "" {
		return t.Configuration.Oauth2Proxy.RedirectURL
	}

	// The redirect URL shall not default to the global one.
	// Instead, it shall be constructed as below code */
	// If the target oidc configuration does not define a redirect URL
	// it will be constructed as https://{name}-{namespace}.domainName/oauth2/callback
	return "https://" + c.GetHost(object) + "/oauth2/callback"
}

// GetOidcIssuerUrl returns the OIDC Provider URL for the given workload target
func (c *OIDCAppsControllerConfig) GetOidcIssuerUrl(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Configuration != nil &&
		t.Configuration.Oauth2Proxy != nil &&
		t.Configuration.Oauth2Proxy.OidcIssuerURL != "" {
		return t.Configuration.Oauth2Proxy.OidcIssuerURL
	}

	if c.Configuration.Oauth2Proxy != nil &&
		c.Configuration.Oauth2Proxy.OidcIssuerURL != "" {
		return c.Configuration.Oauth2Proxy.OidcIssuerURL
	}

	return ""

}

// GetSslInsecureSkipVerify designates if oauth2-proxy shall skip upstream ssl validation
func (c *OIDCAppsControllerConfig) GetSslInsecureSkipVerify(object client.Object) bool {

	t := c.fetchTarget(object)
	if t.Configuration != nil &&
		t.Configuration.Oauth2Proxy != nil &&
		t.Configuration.Oauth2Proxy.SSLInsecureSkipVerify != nil {
		return ptr.Deref(t.Configuration.Oauth2Proxy.SSLInsecureSkipVerify, false)

	}
	if c.Configuration.Oauth2Proxy != nil &&
		c.Configuration.Oauth2Proxy.SSLInsecureSkipVerify != nil {
		return ptr.Deref(c.Configuration.Oauth2Proxy.SSLInsecureSkipVerify, false)
	}
	return false
}

// GetInsecureOidcSkipIssuerVerification designates if oauth2-proxy shall skip OIDC Provider certificate validation
func (c *OIDCAppsControllerConfig) GetInsecureOidcSkipIssuerVerification(object client.Object) bool {

	t := c.fetchTarget(object)
	if t.Configuration != nil && t.Configuration.Oauth2Proxy != nil &&
		t.Configuration.Oauth2Proxy.InsecureOidcSkipIssuerVerification != nil {
		return ptr.Deref(t.Configuration.Oauth2Proxy.InsecureOidcSkipIssuerVerification, false)
	}
	if c.Configuration.Oauth2Proxy != nil &&
		c.Configuration.Oauth2Proxy.InsecureOidcSkipIssuerVerification != nil {
		return ptr.Deref(c.Configuration.Oauth2Proxy.InsecureOidcSkipIssuerVerification, false)

	}
	return false
}

// GetIngressTLSSecretName return the tls secret for the ingress serving certificate for the given workload
func (c *OIDCAppsControllerConfig) GetIngressTLSSecretName(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Ingress != nil && t.Ingress.TLSSecretRef.Name != "" {
		return t.Ingress.TLSSecretRef.Name
	}
	return ""
}

// GetIngressClassName return the ingress class name for the given target
func (c *OIDCAppsControllerConfig) GetIngressClassName(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Ingress != nil {
		return t.Ingress.IngressClassName
	}
	return ""
}

func (c *OIDCAppsControllerConfig) fetchTarget(o client.Object) Target {

	var targets []Target
	for _, t := range c.Targets {
		target := t
		if c.targetMatchesLabels(target, o) {
			targets = append(targets, target)
		}
	}
	if len(targets) > 1 {
		c.log.Info("Multiple targets are fetched", "count", len(targets), "object", o.GetNamespace()+"/"+o.GetName())

	}
	if len(targets) > 0 {
		return targets[0]
	}
	return Target{}
}

// Add namespace support for matching targets
func (c *OIDCAppsControllerConfig) targetMatchesLabels(t Target, o client.Object) bool {
	selector, err := metav1.LabelSelectorAsSelector(t.LabelSelector)
	if err != nil {
		return false
	}
	if t.NamespaceSelector.Size() == 0 {
		return selector.Matches(labels2.Set(o.GetLabels()))
	}
	// Define the namespace object and fill the Name field.
	// Use the Get function.
	if c.client == nil {
		return false
	}
	namespace := &corev1.Namespace{}
	err = c.client.Get(context.TODO(), client.ObjectKey{Name: o.GetNamespace()}, namespace)
	if err != nil {
		return false
	}
	namespaceSelector, err := metav1.LabelSelectorAsSelector(t.NamespaceSelector)
	if err != nil {
		return false
	}

	if t.LabelSelector.Size() == 0 {
		// We don't have a label selector for this target, matching only the namespace selector
		return namespaceSelector.Matches(labels2.Set(namespace.GetLabels()))
	}
	return selector.Matches(labels2.Set(o.GetLabels())) && namespaceSelector.Matches(labels2.Set(namespace.GetLabels()))
}
