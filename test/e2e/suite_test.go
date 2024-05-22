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
	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/controllers"
	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/oidc-apps-controller"
	oidcappswebhook "github.com/gardener/oidc-apps-controller/pkg/webhook"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	autoscalerv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"path/filepath"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func TestSute(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "E2E Suite")
}

var (
	env  *envtest.Environment
	cfg  *rest.Config
	_log = zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true))
	err  error

	ctx    context.Context
	cancel context.CancelFunc
	m      manager.Manager
	c      client.Client
	sch    *runtime.Scheme
)

var _ = BeforeSuite(func() {

	// Setup oidc-apps-controller configuration
	configuration.CreateControllerConfigOrDie(filepath.Join("config", "oidc-apps.yaml"))

	// The oidc-apps reconcilers require autoscaling.k8s.io/v1 API
	env = &envtest.Environment{
		CRDDirectoryPaths: []string{"crds"},
	}

	installWebHooks(env)

	// Start the test environment
	cfg, err = env.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil(), "Failed to create a new test environment")

	// Disable metrics server in controller-runtime
	metricsserver.DefaultBindAddress = "0"

	sch = scheme.Scheme
	err = autoscalerv1.AddToScheme(sch)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(sch.IsGroupRegistered("autoscaling.k8s.io")).Should(BeTrue())

	c, err = client.New(env.Config, client.Options{Scheme: sch})

	// Initialize the test timeout context
	ctx, cancel = context.WithCancel(context.Background())

	// Verify the oidc-apps-controller pod mutating webhook is present
	mutatingWebhookConfiguration := &admissionv1.MutatingWebhookConfiguration{}
	err = c.Get(ctx, client.ObjectKey{
		Namespace: "",
		Name:      "oidc-apps-controller-pods.gardener.cloud",
	}, mutatingWebhookConfiguration)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(mutatingWebhookConfiguration.Webhooks).Should(HaveLen(1))

	// Initialize the controller-runtime manager
	m, err = controllerruntime.NewManager(cfg, controllerruntime.Options{
		Logger: _log,
		WebhookServer: webhook.NewServer(webhook.Options{
			Port:    env.WebhookInstallOptions.LocalServingPort,
			Host:    env.WebhookInstallOptions.LocalServingHost,
			CertDir: env.WebhookInstallOptions.LocalServingCertDir,
			TLSOpts: []func(*tls.Config){func(config *tls.Config) {}},
		}),
		Scheme: sch,
	})
	Expect(err).NotTo(HaveOccurred())

	// Register the webhook server
	server := m.GetWebhookServer()
	server.Register(constants.PodWebHookPath, &webhook.Admission{Handler: &oidcappswebhook.PodMutator{
		Client:  c,
		Decoder: admission.NewDecoder(sch),
	}})

	// Set up the Oidc-Apps Deployment reconciler
	err = controllerruntime.NewControllerManagedBy(m).
		Named("oidc-apps-deployments").
		For(&appsv1.Deployment{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestForOwner(
				m.GetScheme(),
				m.GetRESTMapper(),
				&appsv1.Deployment{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestForOwner(
				m.GetScheme(),
				m.GetRESTMapper(),
				&appsv1.Deployment{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&networkingv1.Ingress{},
			handler.EnqueueRequestForOwner(
				m.GetScheme(),
				m.GetRESTMapper(),
				&appsv1.Deployment{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(oidc_apps_controller.PodMapFuncForDeployment(m)),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Complete(&controllers.DeploymentReconciler{Client: m.GetClient()})
	Expect(err).ShouldNot(HaveOccurred())

	// Set up the Oidc-Apps StatefulSet reconciler
	err = controllerruntime.NewControllerManagedBy(m).
		Named("oidc-apps-statefulsets").
		For(&appsv1.StatefulSet{}).
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestForOwner(
				m.GetScheme(),
				m.GetRESTMapper(),
				&appsv1.StatefulSet{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestForOwner(
				m.GetScheme(),
				m.GetRESTMapper(),
				&appsv1.StatefulSet{},
			),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(oidc_apps_controller.ServiceMapFuncForStatefulset(m)),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Watches(
			&networkingv1.Ingress{},
			handler.EnqueueRequestsFromMapFunc(oidc_apps_controller.IngressMapFuncForStatefulset(m)),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})).
		Complete(&controllers.StatefulSetReconciler{Client: m.GetClient()})
	Expect(err).ShouldNot(HaveOccurred())

	// Start the controller-runtime manager
	go func() {
		defer GinkgoRecover()
		Expect(m.Start(ctx)).Should(Succeed())
	}()

	// Retrieve the cache from the manager
	Expect(m.GetCache().WaitForCacheSync(ctx)).Should(BeTrue())

})

var _ = AfterSuite(func() {
	By("tearing down the controller-runtime manager")
	cancel()
	Eventually(env.Stop()).WithTimeout(2 * time.Second).WithPolling(100 * time.Millisecond).Should(Succeed())
})
