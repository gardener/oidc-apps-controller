// SPDX-FileCopyrightText: Contributors to the Gardener project
// SPDX-License-Identifier: Apache-2.0

// Package controllers handles the main logic for the oidc-apps controller
package controllers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/randutils"
)

var errSecretDoesNotExist = errors.New("secret does not exist")

// cookieSecretBytes is the number of random bytes used for the oauth2-proxy cookie secret.
// oauth2-proxy accepts a 16, 24, or 32 byte key; 32 bytes selects AES-256.
const cookieSecretBytes = 32

// generateCookieSecret returns a random oauth2-proxy cookie secret.
// The value is 32 bytes from crypto/rand, base64 url encoded (no padding). oauth2-proxy
// decodes it back to the raw 32 bytes before it builds the AES cipher.
func generateCookieSecret() (string, error) {
	b := make([]byte, cookieSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate cookie secret: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func createOauth2Secret(ctx context.Context, c client.Client, object client.Object) (corev1.Secret, error) {
	var cfg string

	suffix := randutils.GenerateSha256(object.GetName() + "-" + object.GetNamespace())
	extConfig := configuration.GetOIDCAppsControllerConfig()

	secret := extConfig.GetClientSecret(object)

	opts := []configuration.OptOauth2{
		configuration.WithClientID(extConfig.GetClientID(object)),
		configuration.WithScope(extConfig.GetScope(object)),
		configuration.WithRedirectURL(extConfig.GetRedirectURL(object)),
		configuration.WithOidcIssuerURL(extConfig.GetOidcIssuerURL(object)),
		configuration.EnableSslInsecureSkipVerify(extConfig.GetSslInsecureSkipVerify(object)),
		configuration.EnableInsecureOidcSkipIssuerVerification(extConfig.GetInsecureOidcSkipIssuerVerification(object)),
		configuration.EnableInsecureOidcSkipNonce(extConfig.GetInsecureOidcSkipNonce(object)),
		configuration.WithInsecureOidcAllowUnverifiedEmail(extConfig.GetInsecureOidcAllowUnverifiedEmail(object)),
	}

	// TODO(bobi-wan): do we want to error out when running the controller
	// and a target has no configured oauth secret?
	if secret == "" {
		opts = append(opts, configuration.WithClientSecretFile("/dev/null"))
	} else {
		opts = append(opts, configuration.WithClientSecret(extConfig.GetClientSecret(object)))
	}

	cfg = configuration.NewOAuth2Config(opts...).Parse()

	checksum := randutils.GenerateFullSha256(cfg)

	secretName := constants.SecretNameOauth2Proxy + "-" + suffix

	// Read back the cookie secret: reuse the existing value when present, generate once otherwise.
	// createOrPatchSecret replaces the whole Data map on update, so the value must be carried
	// forward here. Regenerating on every reconcile would rotate the value and drop all sessions.
	cookieSecret, err := reuseOrGenerateCookieSecret(ctx, c, object.GetNamespace(), secretName)
	if err != nil {
		return corev1.Secret{}, err
	}

	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
			Namespace:   object.GetNamespace(),
			Annotations: map[string]string{constants.AnnotationOauth2SecretChecksumKey: checksum},
			Labels: map[string]string{
				constants.LabelKey:       constants.LabelValue,
				constants.SecretLabelKey: constants.Oauth2LabelValue,
			},
		},
		Data: map[string][]byte{
			constants.Oauth2ConfigKey: []byte(cfg),
			constants.CookieSecretKey: []byte(cookieSecret),
		},
	}, nil
}

// reuseOrGenerateCookieSecret returns the cookie secret stored in the named oauth2 secret when it
// is already present, or a freshly generated value when the secret or the key is absent.
func reuseOrGenerateCookieSecret(ctx context.Context, c client.Client, namespace, name string) (string, error) {
	existing := &corev1.Secret{}
	err := c.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, existing)
	switch {
	case err == nil:
		if v, ok := existing.Data[constants.CookieSecretKey]; ok && len(v) > 0 {
			return string(v), nil
		}
	case apierrors.IsNotFound(err):
		// jump to generation.
	default:
		return "", fmt.Errorf("failed to get oauth2 secret %s/%s: %w", namespace, name, err)
	}

	return generateCookieSecret()
}

func createResourceAttributesSecret(object client.Object, targetNamespace string) (corev1.Secret, error) {
	suffix := randutils.GenerateSha256(object.GetName() + "-" + object.GetNamespace())

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
	suffix := randutils.GenerateSha256(object.GetName() + "-" + object.GetNamespace())

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

	kcfg, err = os.ReadFile(filepath.Join(filepath.Clean(path), "kubeconfig")) // #nosec G703 -- kubeconfig is expected to be a file containing the kubeconfig, and the path is controlled by environment variables
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

	token, err = os.ReadFile(filepath.Join(filepath.Clean(path), "token")) // #nosec G703 -- token is expected to be a file containing the token, and the path is controlled by environment variables
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
	suffix := randutils.GenerateSha256(object.GetName() + "-" + object.GetNamespace())

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
