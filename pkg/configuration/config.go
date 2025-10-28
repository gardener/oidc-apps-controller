// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package configuration

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/yaml"

	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/rand"
)

// OIDCAppsControllerConfig is the root configuration node
type OIDCAppsControllerConfig struct {
	Global  Global   `json:"global,omitempty"`
	Targets []Target `json:"targets,omitempty"`
	client  client.Client
	log     logr.Logger
}

// Global holds the concrete target configurations for the auth & authz proxies
type Global struct {
	Oauth2Proxy   *Oauth2ProxyConfig   `json:"oauth2Proxy,omitempty"`
	KubeRbacProxy *KubeRbacProxyConfig `json:"kubeRbacProxy,omitempty"`

	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	DomainName  string            `json:"domainName,omitempty"`

	OidcCABundle    string                  `json:"oidcCABundle,omitempty"`
	OidcCASecretRef *corev1.SecretReference `json:"oidcCASecretRef,omitempty"`
}

// Oauth2ProxyConfig OIDC Provider configuration
type Oauth2ProxyConfig struct {
	Scope                              string `json:"scope,omitempty"`
	ClientID                           string `json:"clientId"`
	ClientSecret                       string `json:"clientSecret,omitempty"`
	RedirectURL                        string `json:"redirectUrl"`
	OidcIssuerURL                      string `json:"oidcIssuerUrl"`
	SSLInsecureSkipVerify              *bool  `json:"sslInsecureSkipVerify,omitempty"`
	InsecureOidcSkipIssuerVerification *bool  `json:"insecureOidcSkipIssuerVerification,omitempty"`
	InsecureOidcSkipNonce              *bool  `json:"insecureOidcSkipNonce,omitempty"`
}

// KubeRbacProxyConfig kube-rbac-proxy configuration
type KubeRbacProxyConfig struct {
	KubeConfigStr string                  `json:"kubeConfigStr,omitempty"`
	KubeSecretRef *corev1.SecretReference `json:"kubeSecretRef,omitempty"`
}

// Target workload selector configuration
type Target struct {
	Name              string                `json:"name"`
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	LabelSelector     *metav1.LabelSelector `json:"labelSelector,omitempty"`
	TargetPort        intstr.IntOrString    `json:"targetPort,omitempty"`
	TargetProtocol    string                `json:"targetProtocol,omitempty"`
	Ingress           *IngressConf          `json:"ingress,omitempty"`
	Global            `json:",omitempty"`
}

// IngressConf holds configuration for the ingress entry-point
type IngressConf struct {
	Create           bool                   `json:"create,omitempty"`
	HostPrefix       string                 `json:"hostPrefix,omitempty"`
	Host             string                 `json:"host,omitempty"`
	Annotations      map[string]string      `json:"annotations,omitempty"`
	Labels           map[string]string      `json:"labels,omitempty"`
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
	once.Do(func() {
		config = &OIDCAppsControllerConfig{}
		for _, o := range opts {
			o(config)
		}

		cf, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			handleError(err, "failed to read extension configuration", path)
		}

		if err = yaml.Unmarshal(cf, config); err != nil {
			handleError(err, "failed to unmarshal extension configuration", path)
		}
	})

	return config
}

// handleError centralizes error handling logic
func handleError(err error, message, path string) {
	if config.log.IsZero() {
		log.SetLogger(zap.New(zap.UseDevMode(true)))
		config.log = log.Log.WithName("oidcAppsExtensionConfig")
	}

	config.log.Error(err, message, "path", path)
	panic("terminating")
}

// GetOIDCAppsControllerConfig returns the loaded configuration
func GetOIDCAppsControllerConfig() *OIDCAppsControllerConfig {
	return config
}

// Match accepts a client.Object and verifies if is a target defined in the controller configuration
func (c *OIDCAppsControllerConfig) Match(o client.Object) bool {
	if c == nil || c.Targets == nil || len(c.Targets) == 0 {
		return false
	}

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
	domain := c.Global.DomainName

	if len(os.Getenv(constants.GardenSeedDomainName)) > 0 {
		domain = os.Getenv(constants.GardenSeedDomainName)
	}

	prefix := object.GetName() + "-" + object.GetNamespace()
	if t.Ingress != nil && t.Ingress.HostPrefix != "" {
		prefix = t.Ingress.HostPrefix + "-" + rand.GenerateSha256(object.GetName()+"-"+object.GetNamespace())
	}

	if t.Ingress != nil && t.Ingress.Host != "" {
		prefix, domain, _ = strings.Cut(t.Ingress.Host, ".")
	}

	if domain == "" {
		return prefix
	}

	return strings.Join([]string{prefix, domain}, ".")
}

// GetUpstreamTarget returns the protocol and port tuple of the target workload
func (c *OIDCAppsControllerConfig) GetUpstreamTarget(object client.Object) string {
	b := strings.Builder{}
	protocol := "http"

	t := c.fetchTarget(object)
	if t.TargetProtocol == "https" {
		protocol = "https"
	}

	b.Grow(9)
	_, _ = b.WriteString("protocol=")
	b.Grow(len(protocol))
	_, _ = b.WriteString(protocol)
	b.Grow(7)
	_, _ = b.WriteString(", port=")
	b.Grow(len(t.TargetPort.String()))
	_, _ = b.WriteString(t.TargetPort.String())

	return b.String()
}

// GetKubeSecretName returns the kubeconfig secret name of the target workload
func (c *OIDCAppsControllerConfig) GetKubeSecretName(object client.Object) string {
	secretName := ""

	t := c.fetchTarget(object)
	if t.KubeRbacProxy != nil &&
		t.KubeRbacProxy.KubeSecretRef != nil &&
		t.KubeRbacProxy.KubeSecretRef.Name != "" {
		return t.KubeRbacProxy.KubeSecretRef.Name
	}

	if c.Global.KubeRbacProxy != nil &&
		c.Global.KubeRbacProxy.KubeSecretRef != nil &&
		c.Global.KubeRbacProxy.KubeSecretRef.Name != "" {
		secretName = c.Global.KubeRbacProxy.KubeSecretRef.Name
	}

	return secretName
}

// GetKubeConfigStr returns the kubeconfig string of the target workload
func (c *OIDCAppsControllerConfig) GetKubeConfigStr(object client.Object) string {
	kubeConfig := ""

	t := c.fetchTarget(object)
	if t.KubeRbacProxy != nil &&
		t.KubeRbacProxy.KubeConfigStr != "" {
		return t.KubeRbacProxy.KubeConfigStr
	}

	if c.Global.KubeRbacProxy != nil &&
		c.Global.KubeRbacProxy.KubeConfigStr != "" {
		kubeConfig = c.Global.KubeRbacProxy.KubeConfigStr
	}

	return kubeConfig
}

// GetOidcCASecretName returns the secret name holding the trusts CA certificate of the OIDC Provider
func (c *OIDCAppsControllerConfig) GetOidcCASecretName(object client.Object) string {
	secretName := ""

	t := c.fetchTarget(object)
	if t.OidcCASecretRef != nil &&
		t.OidcCASecretRef.Name != "" {
		return t.OidcCASecretRef.Name
	}

	if c.Global.OidcCASecretRef != nil &&
		c.Global.OidcCASecretRef.Name != "" {
		secretName = c.Global.OidcCASecretRef.Name
	}

	return secretName
}

// GetOidcCABundle returns the trusted CA bundle certificates of the OIDC Provider
func (c *OIDCAppsControllerConfig) GetOidcCABundle(object client.Object) string {
	var (
		decodedBytes []byte
		err          error
		oidcCABundle string
	)

	t := c.fetchTarget(object)
	if t.OidcCABundle != "" {
		if decodedBytes, err = base64.StdEncoding.DecodeString(t.OidcCABundle); err != nil {
			c.log.Error(err, "failed to decode oidc ca bundle")

			return ""
		}

		return string(decodedBytes)
	}

	if c.Global.OidcCABundle != "" {
		oidcCABundle = c.Global.OidcCABundle
	}

	if decodedBytes, err = base64.StdEncoding.DecodeString(oidcCABundle); err != nil {
		c.log.Error(err, "failed to decode oidc ca bundle")

		return ""
	}

	return string(decodedBytes)
}

// GetClientID returns the OIDC Provider client_id for the given workload target
func (c *OIDCAppsControllerConfig) GetClientID(object client.Object) string {
	if len(os.Getenv(constants.GardenSeedOauth2ProxyClientID)) > 0 {
		return os.Getenv(constants.GardenSeedOauth2ProxyClientID)
	}

	t := c.fetchTarget(object)

	if t.Oauth2Proxy != nil &&
		t.Oauth2Proxy.ClientID != "" {
		return t.Oauth2Proxy.ClientID
	}

	if c.Global.Oauth2Proxy != nil &&
		c.Global.Oauth2Proxy.ClientID != "" {
		return c.Global.Oauth2Proxy.ClientID
	}

	return ""
}

// GetClientSecret returns the OIDC Provider secret for the given target workload
func (c *OIDCAppsControllerConfig) GetClientSecret(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Oauth2Proxy != nil &&
		t.Oauth2Proxy.ClientSecret != "" {
		return t.Oauth2Proxy.ClientSecret
	}

	if c.Global.Oauth2Proxy != nil &&
		c.Global.Oauth2Proxy.ClientSecret != "" {
		return c.Global.Oauth2Proxy.ClientSecret
	}

	return ""
}

// GetScope returns the OIDC Provider scope for the given target workload
func (c *OIDCAppsControllerConfig) GetScope(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Oauth2Proxy != nil &&
		t.Oauth2Proxy.Scope != "" {
		return t.Oauth2Proxy.Scope
	}

	if c.Global.Oauth2Proxy != nil &&
		c.Global.Oauth2Proxy.Scope != "" {
		return c.Global.Oauth2Proxy.Scope
	}

	return ""
}

// GetRedirectURL returns the OIDC Provider redirect URL for the given workload target
func (c *OIDCAppsControllerConfig) GetRedirectURL(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Oauth2Proxy != nil &&
		t.Oauth2Proxy.RedirectURL != "" {
		return t.Oauth2Proxy.RedirectURL
	}

	// The redirect URL shall not default to the global one.
	// Instead, it shall be constructed as below code */
	// If the target oidc configuration does not define a redirect URL
	// it will be constructed as https://{name}-{namespace}.domainName/oauth2/callback
	return "https://" + c.GetHost(object) + "/oauth2/callback"
}

// GetOidcIssuerURL returns the OIDC Provider URL for the given workload target
func (c *OIDCAppsControllerConfig) GetOidcIssuerURL(object client.Object) string {
	t := c.fetchTarget(object)
	if t.Oauth2Proxy != nil &&
		t.Oauth2Proxy.OidcIssuerURL != "" {
		return t.Oauth2Proxy.OidcIssuerURL
	}

	if c.Global.Oauth2Proxy != nil &&
		c.Global.Oauth2Proxy.OidcIssuerURL != "" {
		return c.Global.Oauth2Proxy.OidcIssuerURL
	}

	return ""
}

// GetSslInsecureSkipVerify designates if oauth2-proxy shall skip upstream ssl validation
func (c *OIDCAppsControllerConfig) GetSslInsecureSkipVerify(object client.Object) bool {
	t := c.fetchTarget(object)
	if t.Oauth2Proxy != nil &&
		t.Oauth2Proxy.SSLInsecureSkipVerify != nil {
		return ptr.Deref(t.Oauth2Proxy.SSLInsecureSkipVerify, false)
	}

	if c.Global.Oauth2Proxy != nil &&
		c.Global.Oauth2Proxy.SSLInsecureSkipVerify != nil {
		return ptr.Deref(c.Global.Oauth2Proxy.SSLInsecureSkipVerify, false)
	}

	return false
}

// GetInsecureOidcSkipIssuerVerification designates if oauth2-proxy shall skip OIDC Provider certificate validation
func (c *OIDCAppsControllerConfig) GetInsecureOidcSkipIssuerVerification(object client.Object) bool {
	t := c.fetchTarget(object)
	if t.Oauth2Proxy != nil &&
		t.Oauth2Proxy.InsecureOidcSkipIssuerVerification != nil {
		return ptr.Deref(t.Oauth2Proxy.InsecureOidcSkipIssuerVerification, false)
	}

	if c.Global.Oauth2Proxy != nil &&
		c.Global.Oauth2Proxy.InsecureOidcSkipIssuerVerification != nil {
		return ptr.Deref(c.Global.Oauth2Proxy.InsecureOidcSkipIssuerVerification, false)
	}

	return false
}

// GetInsecureOidcSkipNonce designates if oauth2-proxy shall skip OIDC nonce request parameter
func (c *OIDCAppsControllerConfig) GetInsecureOidcSkipNonce(object client.Object) bool {
	t := c.fetchTarget(object)
	if t.Oauth2Proxy != nil &&
		t.Oauth2Proxy.InsecureOidcSkipNonce != nil {
		return ptr.Deref(t.Oauth2Proxy.InsecureOidcSkipNonce, false)
	}

	if c.Global.Oauth2Proxy != nil &&
		c.Global.Oauth2Proxy.InsecureOidcSkipNonce != nil {
		return ptr.Deref(c.Global.Oauth2Proxy.InsecureOidcSkipNonce, false)
	}

	return false
}

// ShallCreateIngress returns true if the target workload shall create an ingress
func (c *OIDCAppsControllerConfig) ShallCreateIngress(object client.Object) bool {
	t := c.fetchTarget(object)
	if t.Ingress != nil {
		return t.Ingress.Create
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

// GetIngressAnnotations returns the ingress annotations for the given target
func (c *OIDCAppsControllerConfig) GetIngressAnnotations(object client.Object) map[string]string {
	t := c.fetchTarget(object)
	if t.Ingress != nil && t.Ingress.Annotations != nil {
		return t.Ingress.Annotations
	}

	return nil
}

// GetIngressLabels returns the ingress labels for the given target
func (c *OIDCAppsControllerConfig) GetIngressLabels(object client.Object) map[string]string {
	t := c.fetchTarget(object)
	if t.Ingress != nil && t.Ingress.Labels != nil {
		return t.Ingress.Labels
	}

	return nil
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
		return selector.Matches(labels.Set(o.GetLabels()))
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
		return namespaceSelector.Matches(labels.Set(namespace.GetLabels()))
	}

	return selector.Matches(labels.Set(o.GetLabels())) && namespaceSelector.Matches(labels.Set(namespace.GetLabels()))
}

// GetTargetLabelSelector returns the label selector for the given target
func (c *OIDCAppsControllerConfig) GetTargetLabelSelector(o client.Object) *metav1.LabelSelector {
	t := c.fetchTarget(o)

	if t.LabelSelector != nil {
		return t.LabelSelector
	}

	return nil
}
