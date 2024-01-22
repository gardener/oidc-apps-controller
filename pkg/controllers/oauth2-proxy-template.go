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
	"bufio"
	_ "embed"
	"strconv"
	"strings"
)

//go:embed templates/oauth2-proxy.cfg
var oauth2 string

type configParser interface {
	parse() string
}

type optOauth2 func(*oauth2Config)

type oauth2Config struct {
	clientID                           string
	clientSecretFile                   string
	clientSecret                       string
	scope                              string
	redirectUrl                        string
	oidcIssuerUrl                      string
	sslInsecureSkipVerify              bool
	insecureOidcSkipIssuerVerification bool
}

func (o oauth2Config) parse() string {
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
					line = l + "=" + "\"" + o.redirectUrl + "\""
				case "oidc_issuer_url":
					line = l + "=" + "\"" + o.oidcIssuerUrl + "\""
				case "ssl_insecure_skip_verify":
					line = l + "=" + "\"" + strconv.FormatBool(o.sslInsecureSkipVerify) + "\""
				case "insecure_oidc_skip_issuer_verification":
					line = l + "=" + "\"" + strconv.FormatBool(o.insecureOidcSkipIssuerVerification) + "\""

				}

			}
		}
		if len(line) > 0 {
			builder.WriteString(line + "\n")
		}
	}

	b := builder.String()
	return strings.TrimSuffix(b, "\n")
}

func newOAuth2Config(opts ...optOauth2) configParser {
	cfg := oauth2Config{}
	for _, o := range opts {
		o(&cfg)
	}
	return &cfg
}

func withClientId(id string) optOauth2 {
	return func(o *oauth2Config) {
		o.clientID = id
	}
}

func withRedirectUrl(url string) optOauth2 {
	return func(o *oauth2Config) {
		o.redirectUrl = url
	}
}

func withScope(scope string) optOauth2 {
	return func(o *oauth2Config) {
		o.scope = scope
	}
}
func withClientSecret(path string) optOauth2 {
	return func(o *oauth2Config) {
		o.clientSecret = path
	}
}

func withClientSecretFile(path string) optOauth2 {
	return func(o *oauth2Config) {
		o.clientSecretFile = path
	}
}

func withOidcIssuerUrl(url string) optOauth2 {
	return func(o *oauth2Config) {
		o.oidcIssuerUrl = url
	}
}

func enableSslInsecureSkipVerify(b bool) optOauth2 {
	return func(o *oauth2Config) {
		o.sslInsecureSkipVerify = b
	}
}

func enableInsecureOidcSkipIssuerVerification(b bool) optOauth2 {
	return func(o *oauth2Config) {
		o.insecureOidcSkipIssuerVerification = b
	}
}
