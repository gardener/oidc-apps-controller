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
	"crypto/rsa"
	"crypto/x509"
	"io"
)

// CertificateOperations is an interface for the operations that are used to generate certificates with purpose of
// mocking dependencies in tests
type CertificateOperations interface {
	GenerateKey(rand io.Reader, bits int) (*rsa.PrivateKey, error)
	CreateCertificate(rand io.Reader, template, parent *x509.Certificate, pub interface{}, priv interface{}) ([]byte, error)
}

type realCertOps struct{}

func (realCertOps) GenerateKey(rand io.Reader, bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand, bits)
}

func (realCertOps) CreateCertificate(rand io.Reader, template, parent *x509.Certificate, pub interface{}, priv interface{}) ([]byte, error) {
	return x509.CreateCertificate(rand, template, parent, pub, priv)
}
