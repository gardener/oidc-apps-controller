// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

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
