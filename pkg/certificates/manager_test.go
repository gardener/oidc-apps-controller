package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateCABundles(t *testing.T) {
	ops := realCertOps{}
	c := certManager{}
	var err error

	// Generate CA certificate
	c.ca, err = generateCACert(tmp, ops)
	assert.Nil(t, err)

	// Generate TLS certificate
	c.tls, err = generateTLSCert(tmp, []string{"test"}, c.ca)
	assert.Nil(t, err)

	// Generate another CA certificate
	caCert, err := generateCACert(tmp, ops)
	assert.Nil(t, err)

	// Encode the DER bytes to PEM format
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.cert.Raw,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	// Add the second CA certificate to the CA bundle
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
