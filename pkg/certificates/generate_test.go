// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package certificates

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

var tmp string

func TestMain(m *testing.M) {
	tmp, _ = os.MkdirTemp(os.TempDir(), "test-*")

	defer func() {
		_ = os.RemoveAll(tmp)
	}()

	m.Run()
}

func TestGenerateInvalidCACert(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockCertOps := NewMockCertificateOperations(mockCtrl)

	mockCertOps.EXPECT().GenerateKey(keyLength).Return(&rsa.PrivateKey{}, nil)
	mockCertOps.EXPECT().CreateCertificate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&x509.Certificate{}, nil)

	// Since the key and bundle generation are mocked the generateCACert shall return an error
	_, err := generateCACert(".", mockCertOps)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "x509: malformed certificate")
}

func TestGenerateCACert(t *testing.T) {
	ops := realCertOps{}

	// Generate CA bundle
	certCA, err := generateCACert(tmp, ops)
	assert.Nil(t, err)

	// Verify that the bundle is a CA bundle for the oidc-apps-controller
	assert.Contains(t, certCA.cert.Subject.CommonName, "oidc-apps-controller-ca")
	// Verify that the bundle is a CA bundle
	assert.True(t, certCA.cert.IsCA)

	// Verify that the persisted bundle is present
	pemData, err := os.ReadFile(filepath.Join(tmp, "ca.crt"))
	assert.Nil(t, err)
	assert.NotEmpty(t, pemData)

	block, _ := pem.Decode(pemData)
	assert.Equal(t, block.Type, "CERTIFICATE")

	// Parse the bundle
	parsedCA, err := x509.ParseCertificate(block.Bytes)
	assert.Nil(t, err)
	// Verify that the parsed bundle is the same as the generated one
	assert.Equal(t, parsedCA.Subject.CommonName, certCA.cert.Subject.CommonName)
}

func TestGenerateTLSCert(t *testing.T) {
	ops := realCertOps{}
	// Generate CA bundle
	certCA, err := generateCACert(tmp, ops)
	assert.Nil(t, err)

	// Generate TLS bundle
	tlsCert, err := generateTLSCert(tmp, ops, []string{"test"}, certCA)
	assert.Nil(t, err)
	assert.False(t, tlsCert.cert.IsCA)

	// Verify that the TLS bundle has `test` as an expected DNS names value
	assert.Contains(t, tlsCert.cert.DNSNames, "test")

	roots := x509.NewCertPool()
	roots.AddCert(certCA.cert)
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	// Verify that the TLS bundle is signed by the CA's private key
	_, err = tlsCert.cert.Verify(opts)
	assert.Nil(t, err)
}
