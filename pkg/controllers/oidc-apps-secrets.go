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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/rand"
)

var errSecretDoesNotExist = errors.New("secret does not exist")

func createOauth2Secret(object client.Object) (corev1.Secret, error) {
	var cfg string

	suffix := rand.GenerateSha256(object.GetName() + "-" + object.GetNamespace())
	extConfig := configuration.GetOIDCAppsControllerConfig()

	switch extConfig.GetClientSecret(object) {
	case "":
		cfg = configuration.NewOAuth2Config(
			configuration.WithClientID(extConfig.GetClientID(object)),
			configuration.WithClientSecretFile("/dev/null"),
			configuration.WithScope(extConfig.GetScope(object)),
			configuration.WithRedirectURL(extConfig.GetRedirectURL(object)),
			configuration.WithOidcIssuerURL(extConfig.GetOidcIssuerURL(object)),
			configuration.EnableSslInsecureSkipVerify(extConfig.GetSslInsecureSkipVerify(object)),
			configuration.EnableInsecureOidcSkipIssuerVerification(extConfig.GetInsecureOidcSkipIssuerVerification(object)),
			configuration.EnableInsecureOidcSkipNonce(extConfig.GetInsecureOidcSkipNonce(object))).Parse()

	default:
		cfg = configuration.NewOAuth2Config(
			configuration.WithClientID(extConfig.GetClientID(object)),
			configuration.WithClientSecret(extConfig.GetClientSecret(object)),
			configuration.WithScope(extConfig.GetScope(object)),
			configuration.WithRedirectURL(extConfig.GetRedirectURL(object)),
			configuration.WithOidcIssuerURL(extConfig.GetOidcIssuerURL(object)),
			configuration.EnableSslInsecureSkipVerify(extConfig.GetSslInsecureSkipVerify(object)),
			configuration.EnableInsecureOidcSkipIssuerVerification(extConfig.GetInsecureOidcSkipIssuerVerification(object)),
			configuration.EnableInsecureOidcSkipNonce(extConfig.GetInsecureOidcSkipNonce(object))).Parse()
	}

	checksum := rand.GenerateFullSha256(cfg)

	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        constants.SecretNameOauth2Proxy + "-" + suffix,
			Namespace:   object.GetNamespace(),
			Annotations: map[string]string{constants.AnnotationOauth2SecertCehcksumKey: checksum},
			Labels: map[string]string{
				constants.LabelKey:       constants.LabelValue,
				constants.SecretLabelKey: constants.Oauth2LabelValue,
			},
		},
		Data: map[string][]byte{"oauth2-proxy.cfg": []byte(cfg)},
	}, nil
}

func createResourceAttributesSecret(object client.Object, targetNamespace string) (corev1.Secret, error) {
	suffix := rand.GenerateSha256(object.GetName() + "-" + object.GetNamespace())

	// TODO: add configurable resource, subresource
	cfg := configuration.NewResourceAttributes(
		configuration.WithNamespace(targetNamespace),
		configuration.WithSubresource(object.GetName()),
	).Parse()

	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.SecretNameResourceAttributes + "-" + suffix,
			Namespace: object.GetNamespace(),
			Labels: map[string]string{
				constants.LabelKey:       constants.LabelValue,
				constants.SecretLabelKey: constants.RbacLabelValue,
			},
		},
		StringData: map[string]string{"config-file.yaml": cfg},
	}, nil
}

func createKubeconfigSecret(object client.Object) (corev1.Secret, error) {
	suffix := rand.GenerateSha256(object.GetName() + "-" + object.GetNamespace())

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
				Name:      constants.SecretNameKubeconfig + "-" + suffix,
				Namespace: object.GetNamespace(),
				Labels: map[string]string{
					constants.LabelKey:       constants.LabelValue,
					constants.SecretLabelKey: constants.KubeconfigLabelValue,
				},
			},
			StringData: map[string]string{"kubeconfig": string(kubeconfig)},
		}

		return secret, nil
	}

	var (
		path        string
		kcfg, token []byte
		err         error
	)

	path = filepath.Dir(os.Getenv("GARDEN_KUBECONFIG"))

	kcfg, err = os.ReadFile(filepath.Join(filepath.Clean(path), "kubeconfig"))
	if err != nil && os.IsNotExist(err) {
		return corev1.Secret{}, errSecretDoesNotExist
	}

	if err != nil {
		return corev1.Secret{}, fmt.Errorf("error creating kubeconfig secret: %w", err)
	}

	// Token is fetched from either the GARDEN_ACCESS_TOKEN environment variable if present, or from the GARDEN_KUBECONFIG

	if os.Getenv("GARDEN_ACCESS_TOKEN") != "" {
		path = os.Getenv("GARDEN_ACCESS_TOKEN")
	}

	token, err = os.ReadFile(filepath.Join(filepath.Clean(path), "token"))
	if err != nil && os.IsNotExist(err) {
		return corev1.Secret{}, nil
	}

	if err != nil {
		return corev1.Secret{}, errSecretDoesNotExist
	}

	kubeConfig := clientcmdv1.Config{}
	if err = yaml.Unmarshal(kcfg, &kubeConfig); err != nil {
		return corev1.Secret{}, fmt.Errorf("error unmarshalling kubeconfig: %v", err)
	}

	if err != nil {
		return corev1.Secret{}, fmt.Errorf("rror creating kubeconfig secret: %w", err)
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
		return corev1.Secret{}, fmt.Errorf("error marshaling kubeconfig: %v", err)
	}

	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubeconfig-" + suffix,
			Namespace: object.GetNamespace(),
			Labels: map[string]string{
				constants.LabelKey:       constants.LabelValue,
				constants.SecretLabelKey: constants.KubeconfigLabelValue,
			},
		},
		StringData: map[string]string{"kubeconfig": string(k)},
	}, nil
}

func createOidcCaBundleSecret(object client.Object) (corev1.Secret, error) {
	suffix := rand.GenerateSha256(object.GetName() + "-" + object.GetNamespace())

	oidcCABundle := configuration.GetOIDCAppsControllerConfig().GetOidcCABundle(object)
	if len(oidcCABundle) > 0 {
		// TODO: verify the oidcCABundle str, it shall be CA certificates in PEM format
		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.SecretNameOidcCa + "-" + suffix,
				Namespace: object.GetNamespace(),
				Labels: map[string]string{
					constants.LabelKey:       constants.LabelValue,
					constants.SecretLabelKey: constants.OidcCa2LabelValue,
				},
			},
			StringData: map[string]string{"ca.crt": oidcCABundle},
		}

		return secret, nil
	}

	return corev1.Secret{}, errSecretDoesNotExist
}
