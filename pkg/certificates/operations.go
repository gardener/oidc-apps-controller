// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

// CertificateOperations is an interface for the operations that are used to generate certificates with purpose of
// mocking dependencies in tests
type CertificateOperations interface {
	GenerateKey(keyLength int) (*rsa.PrivateKey, error)
	CreateCertificate(template, parent *x509.Certificate, pub any, priv any) (*x509.Certificate, error)
}

type realCertOps struct{}

func (realCertOps) GenerateKey(keyLength int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keyLength)
}

func (realCertOps) CreateCertificate(template, parent *x509.Certificate, pub any, priv any) (*x509.Certificate, error) {
	var (
		certBytes []byte
		err       error
	)
	if certBytes, err = x509.CreateCertificate(rand.Reader, template, parent, pub, priv); err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certBytes)
}
