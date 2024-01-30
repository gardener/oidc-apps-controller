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

package controllers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/constants"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

var errSecretDoesNotExist = errors.New("secret does not exist")

func createOauth2Secret(object client.Object) (corev1.Secret, error) {
	suffix, ok := object.GetAnnotations()[oidc_apps_controller.AnnotationSuffixKey]
	if !ok {
		return corev1.Secret{}, fmt.Errorf("missing suffix annotation")
	}
	extConfig := configuration.GetOIDCAppsControllerConfig()
	var cfg string
	switch extConfig.GetClientSecret(object) {
	case "":
		cfg = newOAuth2Config(
			withClientId(extConfig.GetClientID(object)),
			withClientSecretFile("/dev/null"),
			withScope(extConfig.GetScope(object)),
			withRedirectUrl(extConfig.GetRedirectUrl(object)),
			withOidcIssuerUrl(extConfig.GetOidcIssuerUrl(object)),
			enableSslInsecureSkipVerify(extConfig.GetSslInsecureSkipVerify(object)),
			enableInsecureOidcSkipIssuerVerification(extConfig.GetInsecureOidcSkipIssuerVerification(object)),
		).parse()
	default:
		cfg = newOAuth2Config(
			withClientId(extConfig.GetClientID(object)),
			withClientSecret(extConfig.GetClientSecret(object)),
			withScope(extConfig.GetScope(object)),
			withRedirectUrl(extConfig.GetRedirectUrl(object)),
			withOidcIssuerUrl(extConfig.GetOidcIssuerUrl(object)),
			enableSslInsecureSkipVerify(extConfig.GetSslInsecureSkipVerify(object)),
			enableInsecureOidcSkipIssuerVerification(extConfig.GetInsecureOidcSkipIssuerVerification(object)),
		).parse()
	}

	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oauth2-proxy-" + suffix,
			Namespace: object.GetNamespace(),
			Labels:    map[string]string{oidc_apps_controller.LabelKey: "oauth2"},
		},
		StringData: map[string]string{"oauth2-proxy.cfg": cfg},
	}, nil
}

func createResourceAttributesSecret(object client.Object, targetNamespace string) (corev1.Secret, error) {
	suffix, ok := object.GetAnnotations()[oidc_apps_controller.AnnotationSuffixKey]
	if !ok {
		return corev1.Secret{}, fmt.Errorf("missing suffix annotation")
	}

	// TODO: add configurable resource, subresource
	cfg := newResourceAttributes(
		withNamespace(targetNamespace),
		withSubresource(object.GetName()),
	).parse()
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "resource-attributes-" + suffix,
			Namespace: object.GetNamespace(),
			Labels:    map[string]string{oidc_apps_controller.LabelKey: "rbac"},
		},
		StringData: map[string]string{"config-file.yaml": cfg},
	}, nil
}

func createKubeconfigSecret(object client.Object) (corev1.Secret, error) {
	suffix, ok := object.GetAnnotations()[oidc_apps_controller.AnnotationSuffixKey]
	if !ok {
		return corev1.Secret{}, fmt.Errorf("missing suffix annotation")
	}

	kubeConfigStr := configuration.GetOIDCAppsControllerConfig().GetKubeConfigStr(object)
	if len(kubeConfigStr) > 0 {
		decodestr, err := base64.StdEncoding.DecodeString(kubeConfigStr)
		if err != nil {
			return corev1.Secret{}, fmt.Errorf("kubeconfig is not base64 encoded: %w", err)
		}

		kubeConfig := clientcmdv1.Config{}
		if err = yaml.Unmarshal(decodestr, &kubeConfig); err != nil {
			return corev1.Secret{}, fmt.Errorf("kubeconfig %s, is not in the expected format: %w", decodestr, err)
		}
		kubeconfig, _ := yaml.Marshal(kubeConfig)

		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kubeconfig-" + suffix,
				Namespace: object.GetNamespace(),
				Labels:    map[string]string{oidc_apps_controller.LabelKey: "kubeconfig"},
			},
			StringData: map[string]string{"kubeconfig": string(kubeconfig)},
		}
		return secret, nil
	}

	d := filepath.Dir(os.Getenv("GARDEN_KUBECONFIG"))
	kcfg, err := os.ReadFile(filepath.Join(d, "kubeconfig"))
	if err != nil && os.IsNotExist(err) {
		return corev1.Secret{}, errSecretDoesNotExist
	}
	if err != nil {
		return corev1.Secret{}, fmt.Errorf("Error creating kubeconfig secret: %w", err)
	}
	token, err := os.ReadFile(filepath.Join(d, "token"))
	if err != nil && os.IsNotExist(err) {
		return corev1.Secret{}, nil
	}
	if err != nil {
		return corev1.Secret{}, errSecretDoesNotExist
	}

	kubeConfig := clientcmdv1.Config{}
	if err = yaml.Unmarshal(kcfg, &kubeConfig); err != nil {
		return corev1.Secret{}, fmt.Errorf("Error unmarshalling kubeconfig: %v", err)
	}

	if err != nil {
		return corev1.Secret{}, fmt.Errorf("Error creating kubeconfig secret: %w", err)
	}
	for i, n := range kubeConfig.AuthInfos {
		if n.Name != "extension" {
			continue
		}
		kubeConfig.AuthInfos[i].AuthInfo.TokenFile = ""
		kubeConfig.AuthInfos[i].AuthInfo.Token = string(token)

	}

	k, err := yaml.Marshal(kubeConfig)
	if err != nil {
		return corev1.Secret{}, fmt.Errorf("Error marshaling kubeconfig: %v", err)
	}

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubeconfig-" + suffix,
			Namespace: object.GetNamespace(),
			Labels:    map[string]string{oidc_apps_controller.LabelKey: "kubeconfig"},
		},
		StringData: map[string]string{"kubeconfig": string(k)},
	}

	return secret, nil
}

func createOidcCaBundleSecret(object client.Object) (corev1.Secret, error) {
	suffix, ok := object.GetAnnotations()[oidc_apps_controller.AnnotationSuffixKey]
	if !ok {
		return corev1.Secret{}, fmt.Errorf("missing suffix annotation")
	}
	oidcCABundle := configuration.GetOIDCAppsControllerConfig().GetOidcCABundle(object)
	if len(oidcCABundle) > 0 {
		// TODO: verify the oidcCABundle str, it shall be CA certificates in PEM format
		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "oidcca-" + suffix,
				Namespace: object.GetNamespace(),
				Labels:    map[string]string{oidc_apps_controller.LabelKey: "oidcca"},
			},
			StringData: map[string]string{"ca.crt": oidcCABundle},
		}
		return secret, nil
	}

	return corev1.Secret{}, nil
}
