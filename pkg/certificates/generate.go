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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"k8s.io/client-go/util/cert"
)

type certificateType string

const (
	certCAType          certificateType = "ca"
	certTLSType         certificateType = "tls"
	commonTLSNamePrefix                 = "oidc-apps-controller-webhook"
	commonCANamePrefix                  = "oidc-apps-controller-ca"
	organizationName                    = "gardener.cloud"
	keyLength                           = 3072
)

type bundle struct {
	cert *x509.Certificate
	key  crypto.PrivateKey
}

func generateCACert(path string, ops CertificateOperations) (*bundle, error) {
	// Generate Certificate Private Key
	privateKey, err := ops.GenerateKey(keyLength)
	if err != nil {
		return nil, fmt.Errorf("error generating the CA private key: %w", err)
	}

	serial, err := generateSerial()
	if err != nil {
		return nil, fmt.Errorf("error generating bundle serial number: %w", err)
	}

	certTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   generateCACommonName(commonCANamePrefix),
			Organization: []string{organizationName},
		},
		DNSNames:              []string{"CA"},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(caCertValidity),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// Self-Signed Certificate
	caCert, err := ops.CreateCertificate(certTmpl, certTmpl, privateKey.Public(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("error creating the CA bundle: %w", err)
	}

	b := &bundle{
		key:  privateKey,
		cert: caCert,
	}
	if err := writeBundle(path, b); err != nil {
		return nil, err
	}

	_log.Info("CA certificate generated", "commonName", certTmpl.Subject.CommonName)

	return b, nil
}

func rsaToPem(privateKey *rsa.PrivateKey) ([]byte, error) {
	m, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error marshaling bundle private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: m}), nil
}

func derToPem(certificate *x509.Certificate) ([]byte, error) {
	certDERBytes, err := x509.ParseCertificate(certificate.Raw)
	if err != nil {
		return nil, fmt.Errorf("error parcing bundle: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDERBytes.Raw}), nil
}

func writeBundle(path string, b *bundle) error {
	certPEM, err := derToPem(b.cert)
	if err != nil {
		return err
	}

	keyPEM, err := rsaToPem(b.key.(*rsa.PrivateKey))
	if err != nil {
		return err
	}

	switch {
	case b.cert.IsCA:
		locationCrt := filepath.Join(path, string(certCAType)+".crt")
		locationKey := filepath.Join(path, string(certCAType)+".key")

		if err = cert.WriteCert(locationCrt, certPEM); err != nil {
			return fmt.Errorf("error saving bundle public key: %w", err)
		}

		if err = cert.WriteCert(locationKey, keyPEM); err != nil {
			return fmt.Errorf("error saving bundle private key: %w", err)
		}
	case !b.cert.IsCA:
		locationCrt := filepath.Join(path, string(certTLSType)+".crt")
		locationKey := filepath.Join(path, string(certTLSType)+".key")

		if err = cert.WriteCert(locationCrt, certPEM); err != nil {
			return fmt.Errorf("error saving bundle public key: %w", err)
		}

		if err = cert.WriteCert(locationKey, keyPEM); err != nil {
			return fmt.Errorf("error saving bundle private key: %w", err)
		}
	}

	return nil
}

func generateTLSCert(path string, ops CertificateOperations, dnsnames []string, caBundle *bundle) (*bundle, error) {
	// Generate Certificate Private Key
	privateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return nil, fmt.Errorf("error generating the TLS private key: %w", err)
	}

	serial, err := generateSerial()
	if err != nil {
		return nil, fmt.Errorf("error generating bundle serial number: %w", err)
	}

	// Generate Certificate Template
	certTmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   generateTLSCommonName(commonTLSNamePrefix),
			Organization: []string{organizationName},
		},
		DNSNames:     dnsnames,
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().Add(tlsCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SerialNumber: serial,
	}

	// Certificate
	certificate, err := ops.CreateCertificate(certTmpl, caBundle.cert, privateKey.Public(), caBundle.key)
	if err != nil {
		return nil, fmt.Errorf("error generating the TLS bundle: %w", err)
	}

	b := &bundle{
		cert: certificate,
		key:  privateKey,
	}

	if err = writeBundle(path, b); err != nil {
		return nil, err
	}

	_log.Info("TLS certificate generated", "commonName", certTmpl.Subject.CommonName)

	return b, nil
}

func generateSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64-1))
	if err != nil {
		return nil, err
	}

	serial = new(big.Int).Add(serial, big.NewInt(1))

	return serial, nil
}

func loadTLSFromDisk(path string) (*bundle, error) {
	var (
		err         error
		key, crt    []byte
		block       *pem.Block
		certificate *x509.Certificate
		k           any
	)
	if crt, err = os.ReadFile(filepath.Join(filepath.Clean(path), string(certTLSType)+".crt")); err != nil {
		return nil, err
	}

	if block, _ = pem.Decode(crt); block == nil {
		return nil, errors.New("no PEM block found")
	}

	if certificate, err = x509.ParseCertificate(block.Bytes); err != nil {
		return nil, err
	}

	if key, err = os.ReadFile(filepath.Join(filepath.Clean(path), string(certTLSType)+".key")); err != nil {
		return nil, err
	}

	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("no PEM block found")
	}

	if k, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return nil, err
	}

	return &bundle{
		cert: certificate,
		key:  k.(*rsa.PrivateKey),
	}, nil
}

func loadCAFromDisk(path string) (*bundle, error) {
	var (
		err         error
		key, crt    []byte
		block       *pem.Block
		certificate *x509.Certificate
		k           any
	)
	if crt, err = os.ReadFile(filepath.Join(filepath.Clean(path), string(certCAType)+".crt")); err != nil {
		return nil, err
	}

	if block, _ = pem.Decode(crt); block == nil {
		return nil, errors.New("no PEM block found")
	}

	if certificate, err = x509.ParseCertificate(block.Bytes); err != nil {
		return nil, err
	}

	if key, err = os.ReadFile(filepath.Join(filepath.Clean(path), string(certCAType)+".key")); err != nil {
		return nil, err
	}

	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("no PEM block found")
	}

	if k, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return nil, err
	}

	return &bundle{
		cert: certificate,
		key:  k.(*rsa.PrivateKey),
	}, nil
}
