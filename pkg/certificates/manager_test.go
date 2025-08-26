// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateCABundles(t *testing.T) {
	var err error

	ops := realCertOps{}
	c := certManager{}

	// Generate CA bundle
	c.ca, err = generateCACert(tmp, ops)
	assert.Nil(t, err)

	// Generate TLS bundle
	c.tls, err = generateTLSCert(tmp, ops, []string{"test"}, c.ca)
	assert.Nil(t, err)

	// Generate another CA bundle
	caCert, err := generateCACert(tmp, ops)
	assert.Nil(t, err)

	// Encode the DER bytes to PEM format
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.cert.Raw,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	// Add the second CA bundle to the CA bundle
	caBundle, err := c.updateCABundles("test", pemBytes)
	assert.Nil(t, err)
	assert.True(t, len(caBundle) > len(pemBytes))

	foundSerials := []big.Int{}

	// Loop through the CA bundle and find the serial numbers of the two CA certificates
	for len(caBundle) > 0 {
		var block *pem.Block

		block, caBundle = pem.Decode(caBundle)
		// no pem block is found
		assert.NotNil(t, block)

		if block.Type != "CERTIFICATE" {
			continue
		}

		crt, err := x509.ParseCertificate(block.Bytes)
		assert.Nil(t, err)

		foundSerials = append(foundSerials, *crt.SerialNumber)
	}

	assert.Equal(t, 2, len(foundSerials))
	assert.Contains(t, foundSerials, *c.ca.cert.SerialNumber)
	assert.Contains(t, foundSerials, *caCert.cert.SerialNumber)
}

func TestRemoveCABundles(t *testing.T) {
	var err error

	ops := realCertOps{}
	c := certManager{}

	// Generate CA bundle
	c.ca, err = generateCACert(tmp, ops)
	assert.Nil(t, err)

	// Generate another CA bundle
	caCert, err := generateCACert(tmp, ops)
	assert.Nil(t, err)

	// Encode the DER bytes to PEM format
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.cert.Raw,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	// Add the second CA bundle to the cert Manager
	caBundle, err := c.updateCABundles("test", pemBytes)
	assert.Nil(t, err)
	assert.True(t, len(caBundle) > len(pemBytes))

	// Let's remove the added CA certificate
	removed, err := c.removeCABundle("test", pemBytes)
	assert.Nil(t, err)
	assert.True(t, len(caBundle) > len(removed))

	foundSerials := []string{}

	// Loop through the CA bundle and find the serial numbers of the two CA certificates
	for len(removed) > 0 {
		var block *pem.Block

		block, removed = pem.Decode(removed)
		// no pem block is found
		assert.NotNil(t, block)

		if block.Type != "CERTIFICATE" {
			continue
		}

		crt, err := x509.ParseCertificate(block.Bytes)
		assert.Nil(t, err)

		foundSerials = append(
			foundSerials, crt.SerialNumber.String(),
		)
	}

	assert.Equal(t, 1, len(foundSerials))
	// The first CA certificate part of the manager should be gone
	assert.NotContains(t, foundSerials, c.ca.cert.SerialNumber.String())
	// The second CA certificate should still be present
	assert.Contains(t, foundSerials, caCert.cert.SerialNumber.String())
}

func TestSaveAndLoadCABundle(t *testing.T) {
	var err error

	ops := realCertOps{}
	c := certManager{}

	// Generate CA bundle
	c.ca, err = generateCACert(tmp, ops)
	assert.Nil(t, err)
	err = writeBundle(tmp, c.ca)
	assert.Nil(t, err)
	loaded, err := loadCAFromDisk(tmp)
	assert.Nil(t, err)
	assert.Equal(t, c.ca.cert.SerialNumber, loaded.cert.SerialNumber)
}

func TestSaveAndLoadTLSBundle(t *testing.T) {
	var err error

	ops := realCertOps{}
	c := certManager{}

	// Generate CA bundle
	c.ca, err = generateCACert(tmp, ops)
	assert.Nil(t, err)

	c.tls, err = generateTLSCert(tmp, ops, []string{"test"}, c.ca)
	assert.Nil(t, err)

	err = writeBundle(tmp, c.tls)
	assert.Nil(t, err)

	loaded, err := loadTLSFromDisk(tmp)

	assert.Nil(t, err)
	assert.Equal(t, c.tls.cert.SerialNumber, loaded.cert.SerialNumber)
}
