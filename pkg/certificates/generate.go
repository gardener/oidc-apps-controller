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
	"fmt"
	"math"
	"math/big"
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

type certificate struct {
	cert *x509.Certificate
	key  crypto.PrivateKey
}

func generateCACert(path string, ops CertificateOperations) (*certificate, error) {
	// Generate Certificate Private Key
	privateKey, err := ops.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return nil, fmt.Errorf("error generating the CA private key: %w", err)
	}
	serial, _ := generateSerial()
	if err != nil {
		return nil, fmt.Errorf("error generating certificate serial number: %w", err)
	}
	certTmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   generateCACommonName(commonCANamePrefix),
			Organization: []string{organizationName},
		},
		DNSNames:              []string{"CA"},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().Add(caCertValidity).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// Self-Signed Certificate
	certDERBytes, err := ops.CreateCertificate(rand.Reader, &certTmpl, &certTmpl, privateKey.Public(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("error creating the CA certificate: %w", err)
	}

	var parsedCert *x509.Certificate
	if parsedCert, err = parseAndSaveCert(path, privateKey, certDERBytes); err != nil {
		return nil, err
	}

	return &certificate{
		key:  privateKey,
		cert: parsedCert,
	}, nil
}

func generateTLSCert(path string, dnsnames []string, cacert *certificate) (*certificate, error) {
	// Generate Certificate Private Key
	privateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return nil, fmt.Errorf("error generating the TLS private key: %w", err)
	}
	serial, err := generateSerial()
	if err != nil {
		return nil, fmt.Errorf("error generating certificate serial number: %w", err)
	}

	// Generate Certificate Template
	certTmpl := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   generateTLSCommonName(commonTLSNamePrefix),
			Organization: []string{organizationName},
		},
		DNSNames:     dnsnames,
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().Add(tlsCertValidity).UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SerialNumber: serial,
	}

	// Certificate
	certDERBytes, err := x509.CreateCertificate(rand.Reader, &certTmpl, cacert.cert, privateKey.Public(), cacert.key)
	if err != nil {
		return nil, fmt.Errorf("error generating the TLS certificate: %w", err)
	}
	var parsedCert *x509.Certificate
	if parsedCert, err = parseAndSaveCert(path, privateKey, certDERBytes); err != nil {
		return nil, err
	}

	return &certificate{
		cert: parsedCert,
		key:  privateKey,
	}, nil
}

func parseAndSaveCert(path string, privateKey *rsa.PrivateKey, certDERBytes []byte) (*x509.Certificate, error) {
	parsedCert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		return nil, fmt.Errorf("error parcing certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDERBytes})
	m, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error marshaling certificate private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: m})

	switch {
	case parsedCert.IsCA:
		locationCrt := filepath.Join(path, string(certCAType)+".crt")
		locationKey := filepath.Join(path, string(certCAType)+".key")
		if err = cert.WriteCert(locationCrt, certPEM); err != nil {
			return nil, fmt.Errorf("error saving certificate public key: %w", err)
		}
		if err = cert.WriteCert(locationKey, keyPEM); err != nil {
			return nil, fmt.Errorf("error saving certificate private key: %w", err)
		}
	case !parsedCert.IsCA:
		locationCrt := filepath.Join(path, string(certTLSType)+".crt")
		locationKey := filepath.Join(path, string(certTLSType)+".key")
		if err = cert.WriteCert(locationCrt, certPEM); err != nil {
			return nil, fmt.Errorf("error saving certificate public key: %w", err)
		}
		if err = cert.WriteCert(locationKey, keyPEM); err != nil {
			return nil, fmt.Errorf("error saving certificate private key: %w", err)
		}
	}

	return parsedCert, nil
}

func generateSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64-1))
	if err != nil {
		return nil, err
	}
	serial = new(big.Int).Add(serial, big.NewInt(1))
	return serial, nil
}
