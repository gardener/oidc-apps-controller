// SPDX-FileCopyrightText: Contributors to the Gardener project
// SPDX-License-Identifier: Apache-2.0

//go:generate go tool -modfile=../../tools/go.mod mockgen -package certificates -destination=mocks.go github.com/gardener/oidc-apps-controller/pkg/certificates CertificateOperations
package certificates
