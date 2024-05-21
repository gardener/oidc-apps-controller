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

package e2e

import (
	"context"
	"crypto/tls"
	_ "embed"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"time"

	oidcappswebhook "github.com/gardener/oidc-apps-controller/pkg/webhook"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	ctx    context.Context
	cancel context.CancelFunc
	m      manager.Manager
	c      client.Client
)

var _ = Describe("Oidc Apps Deployment Framework Test", Ordered, func() {

	// Initialize the respective target resources such as deployments and statefulsets
	BeforeAll(func() {
		c, err = client.New(env.Config, client.Options{
			Scheme: scheme.Scheme,
		})
		// Initialize the test timeout context
		ctx, cancel = context.WithTimeout(
			logr.NewContext(context.Background(), _log),
			15*time.Second,
		)

		//TODO: Clean up all debug logs
		_log.Info("env", "LocalServingPort", env.WebhookInstallOptions.LocalServingPort)
		_log.Info("env", "LocalServingHost", env.WebhookInstallOptions.LocalServingHost)
		_log.Info("env", "LocalServingCertDir", env.WebhookInstallOptions.LocalServingCertDir)

		// Initialize the controller-runtime manager
		m, err = controllerruntime.NewManager(cfg, controllerruntime.Options{
			Logger: _log,
			WebhookServer: webhook.NewServer(webhook.Options{
				Port:    env.WebhookInstallOptions.LocalServingPort,
				Host:    env.WebhookInstallOptions.LocalServingHost,
				CertDir: env.WebhookInstallOptions.LocalServingCertDir,
				TLSOpts: []func(*tls.Config){func(config *tls.Config) {}},
			}),
		})
		Expect(err).NotTo(HaveOccurred())

		server := m.GetWebhookServer()
		server.Register(constants.PodWebHookPath, &webhook.Admission{Handler: &oidcappswebhook.PodMutator{
			Client:  c,
			Decoder: admission.NewDecoder(scheme.Scheme),
		}})

		go func() {
			defer GinkgoRecover()
			Expect(m.GetWebhookServer().Start(context.TODO())).Should(Succeed())
			_log.Info("Webhook server started")
			Expect(m.GetCache().Start(context.TODO())).Should(Succeed())
			_log.Info("Cache started")
		}()

		_log.Info("Manager started")

		conf := &admissionv1.MutatingWebhookConfiguration{}
		err = c.Get(context.TODO(), client.ObjectKey{
			Namespace: "",
			Name:      "oidc-apps-controller-pods.gardener.cloud",
		}, conf)
		_log.Info("Webhook configuration", "conf", conf)
		Expect(err).ShouldNot(HaveOccurred())

	})

	AfterAll(func() {
		cancel()
	})

	Context("when a deployment is a target", Ordered, func() {

		var (
			deployment *appsv1.Deployment
			replicaSet *appsv1.ReplicaSet
			pod        *corev1.Pod
		)

		BeforeAll(func() {
			// Create a deployment and the downstream replicaset and the pod as there is no controller to create them
			time.Sleep(1 * time.Second)
			deployment = createDeployment()
			Expect(c.Create(context.TODO(), deployment)).Should(Succeed())

			replicaSet = createReplicaSet(deployment)
			Expect(c.Create(context.TODO(), replicaSet)).Should(Succeed())

			pod = createPod(replicaSet)
			Expect(c.Create(context.TODO(), pod)).Should(Succeed())

		})

		AfterAll(func() {
			Expect(client.IgnoreNotFound(c.Delete(context.TODO(), deployment))).Should(Succeed())
			Expect(client.IgnoreNotFound(c.Delete(context.TODO(), replicaSet))).Should(Succeed())
			Expect(client.IgnoreNotFound(c.Delete(context.TODO(), pod))).Should(Succeed())
		})

		It("there shall be auth & autz proxies present in the deployment", func() {

			pod := &corev1.Pod{}
			Expect(c.Get(ctx, client.ObjectKey{
				Namespace: "default",
				Name:      "nginx-pod",
			}, pod)).Should(Succeed())

			Expect(pod.Spec.Containers).Should(HaveLen(3))

		})
		It("there shall be ingress present in the deployment namespace", func() {})
		It("there shall be service present in the deployment namespace", func() {})
		It("there shall be outh2 and kube-rbac secrets present in the deployment namespace", func() {})
		When("the deployment is deleted", func() {
			It("there shall be no auth & autz proxies present in the deployment", func() {})
		})
	})
	Context("when a deployment is not a target", func() {
		It("there shall be no auth & autz proxies present in the deployment", func() {})
	})

})
