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
	"bufio"
	_ "embed"
	"strconv"
	"strings"
)

//go:embed templates/oauth2-proxy.cfg
var oauth2 string

type configParser interface {
	Parse() string
}

// OptOauth2 is a function that modifies the oauth2Config
type OptOauth2 func(*oauth2Config)

type oauth2Config struct {
	clientID                           string
	clientSecretFile                   string
	clientSecret                       string
	scope                              string
	redirectURL                        string
	oidcIssuerURL                      string
	sslInsecureSkipVerify              bool
	insecureOidcSkipIssuerVerification bool
	insecureOidcSkipNonce              bool
}

// Parse returns the parsed oauth2 config
func (o *oauth2Config) Parse() string {
	var builder strings.Builder

	scanner := bufio.NewScanner(strings.NewReader(oauth2))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip if line starts with #
		if strings.HasPrefix(line, "#") {
			continue
		}
		// If line contains '=', replace the value after the first '='
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				l := strings.TrimSpace(parts[0])
				switch l {
				case "scope":
					line = l + "=" + "\"" + o.scope + "\""
				case "client_id":
					line = l + "=" + "\"" + o.clientID + "\""
				case "client_secret":
					if o.clientSecret != "" {
						line = l + "=" + "\"" + o.clientSecret + "\""
					} else {
						line = ""
					}
				case "client_secret_file":
					if o.clientSecret == "" {
						line = l + "=" + "\"" + o.clientSecretFile + "\""
					} else {
						line = ""
					}
				case "redirect_url":
					line = l + "=" + "\"" + o.redirectURL + "\""
				case "oidc_issuer_url":
					line = l + "=" + "\"" + o.oidcIssuerURL + "\""
				case "ssl_insecure_skip_verify":
					line = l + "=" + "\"" + strconv.FormatBool(o.sslInsecureSkipVerify) + "\""
				case "insecure_oidc_skip_issuer_verification":
					line = l + "=" + "\"" + strconv.FormatBool(o.insecureOidcSkipIssuerVerification) + "\""
				case "insecure_oidc_skip_nonce":
					line = l + "=" + "\"" + strconv.FormatBool(o.insecureOidcSkipNonce) + "\""
				}
			}
		}

		if len(line) > 0 {
			_, _ = builder.WriteString(line + "\n")
		}
	}

	b := builder.String()

	return strings.TrimSuffix(b, "\n")
}

// NewOAuth2Config returns a new oauth2 config
func NewOAuth2Config(opts ...OptOauth2) configParser {
	cfg := oauth2Config{}
	for _, o := range opts {
		o(&cfg)
	}

	return &cfg
}

// WithClientID sets the client id
func WithClientID(id string) OptOauth2 {
	return func(o *oauth2Config) {
		o.clientID = id
	}
}

// WithRedirectURL sets the redirect url
func WithRedirectURL(url string) OptOauth2 {
	return func(o *oauth2Config) {
		o.redirectURL = url
	}
}

// WithScope sets the scope
func WithScope(scope string) OptOauth2 {
	return func(o *oauth2Config) {
		o.scope = scope
	}
}

// WithClientSecret sets the client secret
func WithClientSecret(path string) OptOauth2 {
	return func(o *oauth2Config) {
		o.clientSecret = path
	}
}

// WithClientSecretFile sets the client secret file
func WithClientSecretFile(path string) OptOauth2 {
	return func(o *oauth2Config) {
		o.clientSecretFile = path
	}
}

// WithOidcIssuerURL sets the oidc issuer url
func WithOidcIssuerURL(url string) OptOauth2 {
	return func(o *oauth2Config) {
		o.oidcIssuerURL = url
	}
}

// EnableSslInsecureSkipVerify sets the ssl insecure skip verify
func EnableSslInsecureSkipVerify(b bool) OptOauth2 {
	return func(o *oauth2Config) {
		o.sslInsecureSkipVerify = b
	}
}

// EnableInsecureOidcSkipIssuerVerification sets the insecure oidc skip issuer verification
func EnableInsecureOidcSkipIssuerVerification(b bool) OptOauth2 {
	return func(o *oauth2Config) {
		o.insecureOidcSkipIssuerVerification = b
	}
}

// EnableInsecureOidcSkipNonce sets the insecure oidc skip nonce
func EnableInsecureOidcSkipNonce(b bool) OptOauth2 {
	return func(o *oauth2Config) {
		o.insecureOidcSkipNonce = b
	}
}
