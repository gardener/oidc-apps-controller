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

package certificates

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateCACommonName(t *testing.T) {
	generatedName := generateCACommonName("oidc-apps-controller-ca")

	expectedPrefix := "oidc-apps-controller-ca-"
	assert.Contains(t, generatedName, expectedPrefix)

	randomStringPart := strings.TrimPrefix(generatedName, expectedPrefix)
	assert.Equal(t, 5, len(randomStringPart),
		fmt.Sprintf("generatedName: %s, expectedPrefix: %s", generatedName, expectedPrefix),
	)
	assert.Equal(t, generatedName, generateCACommonName("oidc-apps-controller-ca-"))
}

func TestGenerateTLSCommonName(t *testing.T) {
	generatedName := generateTLSCommonName("oidc-apps-controller")
	expectedPrefix := "oidc-apps-controller-webhook-"
	assert.Contains(t, generatedName, expectedPrefix)

	randomStringPart := strings.TrimPrefix(generatedName, expectedPrefix)
	assert.Equal(t, 5, len(randomStringPart),
		fmt.Sprintf("generatedName: %s, expectedPrefix: %s", generatedName, expectedPrefix),
	)

	assert.Equal(t, generatedName, generateTLSCommonName("oidc-apps-controller"))
}

func TestGenerateRandomString(t *testing.T) {
	randomString := generateRandomString(5)
	assert.NotEqual(t, randomString, generateRandomString(5))
}
