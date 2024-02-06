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
	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/controllers"
	"github.com/gardener/oidc-apps-controller/pkg/webhook"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"os"
	"path/filepath"
	controllerruntime "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	. "sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"strings"
	"time"
)

//go:embed config.yaml
var configFile string

var (
	env        *Environment
	mgr        controllerruntime.Manager
	client     ctrlclient.Client
	_log       logr.Logger
	tmpDir     string
	deployment *appsv1.Deployment
	cancel     context.CancelFunc
)

var _ = BeforeSuite(func() {
	var err error
	// Initialize logging
	_log = zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true))
	logf.SetLogger(_log)

	//Initialize test environment
	env = &Environment{}
	installWebHooks(env)

	Expect(env.Start()).NotTo(BeNil())

	//Initialize controller-runtime manager
	mgr, err = manager.New(env.Config, manager.Options{
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Port:    env.WebhookInstallOptions.LocalServingPort,
			Host:    env.WebhookInstallOptions.LocalServingHost,
			CertDir: env.WebhookInstallOptions.LocalServingCertDir,
			TLSOpts: []func(*tls.Config){func(config *tls.Config) {}},
		}),
	})
	Expect(err).NotTo(HaveOccurred())
	server := mgr.GetWebhookServer()
	client, err = ctrlclient.New(env.Config, ctrlclient.Options{})
	Expect(err).NotTo(HaveOccurred())
	server.Register(
		constants.DeploymentWebHookPath,
		&ctrlwebhook.Admission{Handler: &webhook.DeploymentMutator{
			Client:          client,
			Decoder:         admission.NewDecoder(runtime.NewScheme()),
			ImagePullSecret: "",
		}},
	)

	// Initialize oidc-apps deployment reconciler
	err = controllerruntime.NewControllerManagedBy(mgr).
		Named("oidc-apps-deployments").
		For(&appsv1.Deployment{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.Deployment{},
			),
		).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.Deployment{},
			),
		).
		Watches(
			&networkingv1.Ingress{},
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(),
				mgr.GetRESTMapper(),
				&appsv1.Deployment{},
			),
		).
		Complete(&controllers.DeploymentReconciler{Client: mgr.GetClient()})
	Expect(err).NotTo(HaveOccurred())

	// Start manager
	var ctx context.Context
	ctx, cancel = context.WithCancel(context.Background())

	go func() {
		Expect(mgr.Start(ctx)).NotTo(HaveOccurred())
	}()

})

var _ = AfterSuite(func() {
	cancel()
	Expect(env.Stop()).NotTo(HaveOccurred())
	Expect(os.RemoveAll(tmpDir)).NotTo(HaveOccurred())
})

var _ = Describe("Deployment target", func() {

	BeforeEach(func() {
		Expect(env.Config).NotTo(BeNil())
	})

	It("A deployment matching target labelSelectors shall be enhanced with the  auth & autz proxies", func() {
		// Create oidc-apps controller config
		tmpDir = GinkgoT().TempDir()
		Expect(
			os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(configFile), 0444),
		).NotTo(HaveOccurred())

		configuration.CreateControllerConfigOrDie(
			filepath.Join(tmpDir, "config.yaml"),
			configuration.WithClient(client),
			configuration.WithLog(_log),
		)

		deployment = createDeployment()

		Eventually(func() error {
			return client.Create(context.TODO(), deployment)
		}, 1*time.Second).ShouldNot(HaveOccurred())

		Expect(
			client.Get(context.TODO(), types.NamespacedName{Namespace: "default", Name: "nginx"}, deployment),
		).NotTo(HaveOccurred())

		By("verifying containers", func() {
			expectedContainerImages := []string{"kube-rbac-proxy-watcher", "oauth2-proxy", "nginx"}

			Expect(len(deployment.Spec.Template.Spec.Containers)).To(Equal(3))

			for _, c := range deployment.Spec.Template.Spec.Containers {
				image, _, ok := strings.Cut(c.Image, ":")
				Expect(ok).To(BeTrue())
				n := strings.SplitAfter(image, "/")
				Expect(n[len(n)-1]).To(BeElementOf(expectedContainerImages))
			}
		})
		By("verifying init container", func() {
			Expect(len(deployment.Spec.Template.Spec.InitContainers)).To(Equal(1))
			Expect(deployment.Spec.Template.Spec.InitContainers[0].Image).To(ContainSubstring("curl"))
		})

		By("verifying secrets", func() {
			secretList := &corev1.SecretList{}
			Eventually(func() bool {
				err := client.List(context.TODO(), secretList, &ctrlclient.ListOptions{Namespace: "default"})
				return err == nil && len(secretList.Items) > 0
			}, 10*time.Second, 1*time.Second).Should(BeTrue())

			Expect(len(secretList.Items)).To(Equal(2))
			expectedSecretNames := []string{"oauth2-proxy", "resource-attributes"}
			for _, s := range secretList.Items {
				suffix, found := deployment.ObjectMeta.Annotations[constants.AnnotationSuffixKey]
				Expect(found).To(BeTrue())
				Expect(strings.TrimSuffix(s.Name, "-"+suffix)).To(BeElementOf(expectedSecretNames))
			}
		})
	})
})
