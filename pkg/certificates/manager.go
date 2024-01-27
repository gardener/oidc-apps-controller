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
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"sync"
	"time"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	tlsCertValidity           = time.Hour * time.Duration(360)     // 15d
	tlsCertRotation           = tlsCertValidity - (time.Hour * 10) // Rotate 10 hours before expire
	caCertValidity            = time.Hour * time.Duration(720)     // 30d
	caCertRotation            = caCertValidity - (time.Hour * 10)  // Rotate 10 hours before expire
	deploymentsWebhookSuffix  = "-deployments.gardener.cloud"
	statefulSetsWebhookSuffix = "-statefulsets.gardener.cloud"
	podsWebhookSuffix         = "-pods.gardener.cloud"
)

type certManager struct {
	// Path to store the certificates
	certPath string
	// SAN records for the TLS certificate
	dnsNames []string
	// Webhook resource reference
	webhookKey types.NamespacedName
	// K8S Client for updating the webhook CABundle resource
	client client.Client
	// Managed Certificates
	ca, tls *certificate
	log     logr.Logger
	manager.LeaderElectionRunnable
}

// certManager is a controller-runtime runnable, managing a tuple of CA and TLS certificates for the webhook
var _ manager.Runnable = &certManager{}
var _ manager.LeaderElectionRunnable = &certManager{}

var webhookUpdateRetry = wait.Backoff{
	Steps:    5,
	Duration: 1 * time.Second,
	Factor:   1.0,
	Jitter:   0.5,
}

// New creates a new controller-runtime runnable providing
// certificate rotation for the service endpoint of the mutating webhook
func New(l logr.Logger, certPath string, objectKey types.NamespacedName, c client.Client, config *rest.Config) (manager.Runnable, error) {

	runnable := &certManager{
		certPath:   certPath,
		client:     c,
		webhookKey: objectKey,
		log:        l.WithName("certificate-manager"),
	}

	dnsNames := []string{objectKey.Name}
	if objectKey.Namespace != "" {
		prefix := objectKey.Name + "." + objectKey.Namespace
		dnsNames = append(dnsNames,
			prefix,
			prefix+".svc",
			prefix+".svc.cluster",
			prefix+".svc.cluster.local",
		)
	}
	runnable.dnsNames = dnsNames

	var err error
	// Generating CA certificate
	if runnable.ca, err = generateCACert(certPath, realCertOps{}); err != nil {
		return nil, err
	}

	// Generating TLS certificate
	if runnable.tls, err = generateTLSCert(certPath, dnsNames, runnable.ca); err != nil {
		return nil, err
	}

	// update CA Bundle in webhooks
	cl, err := client.New(config, client.Options{})
	if err != nil {
		return nil, err
	}

	webhook := &v1.MutatingWebhookConfiguration{}
	if err := retry.RetryOnConflict(webhookUpdateRetry, func() error {
		if err := cl.Get(context.Background(), objectKey, webhook); err != nil {
			return err
		}
		runnable.initializeWebhookCABundle(webhook)
		return cl.Update(context.Background(), webhook)
	}); err != nil {
		return nil, err
	}

	return runnable, nil
}

func (c *certManager) NeedLeaderElection() bool {
	return false
}

func (c *certManager) initializeWebhookCABundle(oidcWebhook *v1.MutatingWebhookConfiguration) {
	for i, w := range oidcWebhook.Webhooks {
		if w.Name != c.webhookKey.Name+deploymentsWebhookSuffix &&
			w.Name != c.webhookKey.Name+statefulSetsWebhookSuffix &&
			w.Name != c.webhookKey.Name+podsWebhookSuffix {
			continue
		}

		bundle, err := c.updateCABundles(w.Name, w.ClientConfig.CABundle)
		if err != nil {
			c.log.Error(err, "Error updating webhook CA Bundles")
			break
		}
		oidcWebhook.Webhooks[i].ClientConfig.CABundle = bundle
	}
}

func (c *certManager) updateWebhookCABundle(oidcWebhook *v1.MutatingWebhookConfiguration) {

	for i, w := range oidcWebhook.Webhooks {
		if w.Name != c.webhookKey.Name+deploymentsWebhookSuffix &&
			w.Name != c.webhookKey.Name+statefulSetsWebhookSuffix &&
			w.Name != c.webhookKey.Name+podsWebhookSuffix {
			continue
		}

		bundle, err := c.updateCABundles(w.Name, w.ClientConfig.CABundle)
		if err != nil {
			c.log.Error(err, "Error updating webhook CA Bundle")
			break
		}
		oidcWebhook.Webhooks[i].ClientConfig.CABundle = bundle
	}
}

func (c *certManager) Start(ctx context.Context) error {
	c.log.Info("Starting webhook certificate manager")
	runnableWaitGroup := &sync.WaitGroup{}
	runnableWaitGroup.Add(1)
	go func() {
		defer runnableWaitGroup.Done()
		wg := &sync.WaitGroup{}
		// Starting two tickers routines
		wg.Add(2)
		go c.rotateCACert(ctx, wg)
		go c.rotateTLSCert(ctx, wg)
		<-ctx.Done() // Waiting for the controller-runtime.Manager to close the context
		c.log.Info("Shutting down the webhook certificate manager")
		wg.Wait()
	}()

	runnableWaitGroup.Wait() // Done with the certmanager
	return nil
}

func (c *certManager) rotateTLSCert(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	tlsTicker := time.NewTicker(tlsCertRotation)
	defer tlsTicker.Stop()
OuterLoop:
	for {
		select {
		case <-tlsTicker.C:
			t, err := generateTLSCert(c.certPath, c.dnsNames, c.ca)
			if err != nil {
				c.log.Error(err, "Error rotating TLS certificate")
			}
			c.tls.key = t.key
			c.tls.cert = t.cert
			c.log.Info("TLS certificate is rotated",
				"serial", c.tls.cert.SerialNumber.String(),
				"NotAfter", c.tls.cert.NotAfter)
		case <-ctx.Done():
			c.log.Info("Shutting down the TLS certificate rotation")
			break OuterLoop
		}
	}
}

func (c *certManager) rotateCACert(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	caTicker := time.NewTicker(caCertRotation) // 10 hours before the CA certificate expires
	defer caTicker.Stop()
OuterLoop:
	for {
		select {
		case <-caTicker.C:
			crt, err := generateCACert(c.certPath, realCertOps{})
			if err != nil {
				c.log.Error(err, "Error rotating CA certificate")
			}
			c.ca.key = crt.key
			c.ca.cert = crt.cert
			c.log.Info("CA certificate is rotated",
				"serial", c.ca.cert.SerialNumber.String(),
				"NotAfter", c.ca.cert.NotAfter)
			c.updateWebhookConfiguration(ctx)
			t, _ := generateTLSCert(c.certPath, c.dnsNames, c.ca)
			c.tls.key = t.key
			c.tls.cert = t.cert
			c.log.Info("TLS certificate is rotated",
				"serial", c.tls.cert.SerialNumber.String(),
				"NotAfter", c.tls.cert.NotAfter)
		case <-ctx.Done():
			c.log.Info("Shutting down the CA certificate rotation")
			break OuterLoop
		}
	}

}

func (c *certManager) updateWebhookConfiguration(ctx context.Context) {

	webhook := &v1.MutatingWebhookConfiguration{}

	if err := retry.RetryOnConflict(webhookUpdateRetry, func() error {
		if err := c.client.Get(context.Background(), c.webhookKey, webhook); err != nil {
			return err
		}

		c.updateWebhookCABundle(webhook)
		return c.client.Update(ctx, webhook)
	}); err != nil {
		// panic if we cannot get/update the webhook
		c.log.Error(err, "Error updating webhook")
		os.Exit(1)
	}

}

func (c *certManager) updateCABundles(name string, caBundle []byte) ([]byte, error) {
	c.log.Info("Updating webhook CA bundle", "webhook", name)
	updatedCAs, currentCAs := []x509.Certificate{}, []x509.Certificate{}
	for len(caBundle) > 0 {
		var block *pem.Block
		block, caBundle = pem.Decode(caBundle)
		// no pem block is found
		if block == nil {
			c.log.Info("No certificate is present in the CA Bundle", "webhook", name)
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		// Add bundle to the temp storage
		currentCAs = append(currentCAs, *crt)
		c.log.Info("Certificate is added to the CA Bundle", "webhook",
			name, "serial", crt.SerialNumber.String(),
		)
	}

	// Clean up expired certs or the cert with the currently generated CN
	for _, ca := range currentCAs {
		// ca is before now, hence it is expired
		if ca.NotAfter.Compare(time.Now().UTC()) == -1 {
			c.log.Info("Certificate is expired, skipping from temp storage", "webhook", name, "serial",
				ca.SerialNumber.String())
			continue
		}
		updatedCAs = append(updatedCAs, ca)
	}
	// add the new CA certificate
	updatedCAs = append(updatedCAs, *c.ca.cert)
	c.log.Info("Certificate CA Bundle length", "length", len(updatedCAs))

	var caBundleSlice []byte
	for _, ca := range updatedCAs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.Raw,
		}

		caBundleSlice = append(caBundleSlice, pem.EncodeToMemory(block)...)

		c.log.Info("Certificate added to the CA Bundle",
			"webhook", name,
			"commonName", ca.Subject.CommonName,
			"serial", ca.SerialNumber.String(),
			"size", len(caBundleSlice),
		)
	}

	return caBundleSlice, nil
}
