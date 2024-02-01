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

package test

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/webhook"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	adminssionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var tmpDir string

//go:embed config.yaml
var configFile string

var _log = zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true))

var _ = BeforeSuite(func() {
	tmpDir = GinkgoT().TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(configFile), 0444)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(os.RemoveAll, tmpDir)
})

var _ = Describe("Oidc Apps Deployment MutatingWebhook Framework Test", func() {
	var (
		ctx        context.Context
		cancel     context.CancelFunc
		fakeClient client.Client
		decoder    *admission.Decoder
	)

	// Initialize the test environment
	BeforeEach(func() {

		ctx, cancel = context.WithTimeout(
			logr.NewContext(context.Background(), _log),
			30*time.Second,
		)

		s := runtime.NewScheme()
		fakeClient = fake.NewClientBuilder().WithScheme(s).Build()
		decoder = admission.NewDecoder(runtime.NewScheme())
		configuration.CreateControllerConfigOrDie(
			filepath.Join(tmpDir, "config.yaml"),
			configuration.WithClient(fakeClient),
			configuration.WithLog(_log),
		)
	})

	AfterEach(func() {
		cancel()
	})
	Context("when the deployment is not a target", func() {

		deployment := &appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
			ObjectMeta: metav1.ObjectMeta{Name: "test-deployment", Namespace: "default"},
			Spec:       appsv1.DeploymentSpec{},
		}
		rawDeployment, err := json.Marshal(deployment)
		Expect(err).NotTo(HaveOccurred())

		It("should allow the admission request with nil patch", func() {
			// Create a Deployment object

			mutator := webhook.DeploymentMutator{
				Client:  fakeClient,
				Decoder: decoder,
			}
			req := admission.Request{
				AdmissionRequest: adminssionv1.AdmissionRequest{
					UID:       "uid-request",
					Kind:      metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
					Resource:  metav1.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
					Namespace: "default",
					Operation: adminssionv1.Create,
					Object: runtime.RawExtension{
						Raw: rawDeployment,
					},
				},
			}
			resp := mutator.Handle(ctx, req)
			Expect(resp.Allowed).To(BeTrue())
			Expect(resp.Patch).To(BeNil())
			Expect(resp.PatchType).To(BeNil())
		})
	})
	Context("when the deployment is a target", func() {
		deployment := &appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
			ObjectMeta: metav1.ObjectMeta{Name: "nginx", Namespace: "nginx", Labels: map[string]string{"app": "nginx"}},
			Spec:       appsv1.DeploymentSpec{},
		}
		rawDeployment, err := json.Marshal(deployment)
		Expect(err).NotTo(HaveOccurred())

		It("should allow the admission request with patch not being nil", func() {
			// Create a Deployment object

			mutator := webhook.DeploymentMutator{
				Client:  fakeClient,
				Decoder: decoder,
			}
			req := admission.Request{
				AdmissionRequest: adminssionv1.AdmissionRequest{
					UID:       "uid-request",
					Kind:      metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
					Resource:  metav1.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
					Namespace: "default",
					Operation: adminssionv1.Create,
					Object: runtime.RawExtension{
						Raw: rawDeployment,
					},
				},
			}
			resp := mutator.Handle(ctx, req)
			_log.Info("resp", "resp", resp)
			Expect(resp.Allowed).To(BeTrue())
			Expect(resp.Patches).ToNot(BeNil())
			Expect(*resp.PatchType).To(BeEquivalentTo(adminssionv1.PatchTypeJSONPatch))

			By("verifying patched deployment", func() {
				patchBytes, err := json.Marshal(resp.Patches)
				Expect(err).NotTo(HaveOccurred())
				decodedPatch, err := jsonpatch.DecodePatch(patchBytes)
				Expect(err).NotTo(HaveOccurred())

				// Apply the patch
				patchDeploymentBytes, err := decodedPatch.Apply(rawDeployment)
				Expect(err).NotTo(HaveOccurred())

				// Deserialize the patched Deployment back into a struct
				var modifiedDeployment appsv1.Deployment
				err = json.Unmarshal(patchDeploymentBytes, &modifiedDeployment)
				Expect(err).NotTo(HaveOccurred())
				_log.Info("modifiedDeployment", "modifiedDeployment", modifiedDeployment)
				By("verifying containers", func() {
					expectedContainerImages := []string{"kube-rbac-proxy-watcher", "oauth2-proxy"}

					Expect(len(modifiedDeployment.Spec.Template.Spec.Containers)).To(Equal(2))

					for _, c := range modifiedDeployment.Spec.Template.Spec.Containers {
						image, _, ok := strings.Cut(c.Image, ":")
						Expect(ok).To(BeTrue())
						n := strings.SplitAfter(image, "/")
						Expect(n[len(n)-1]).To(BeElementOf(expectedContainerImages))
					}
				})
				By("verifying init container", func() {
					Expect(len(modifiedDeployment.Spec.Template.Spec.InitContainers)).To(Equal(1))
					Expect(modifiedDeployment.Spec.Template.Spec.InitContainers[0].Image).To(ContainSubstring("curl"))
				})
			})
		})
	})
})
