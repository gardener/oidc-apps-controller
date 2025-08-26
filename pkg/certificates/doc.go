// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

//go:generate go tool mockgen -package certificates -destination=mocks.go github.com/gardener/oidc-apps-controller/pkg/certificates CertificateOperations
package certificates
