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

package webhook

import (
	"context"

	"fmt"
	"net/http"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/constants"
)

// Register the webhook with the server
var _ admission.Handler = &DeploymentMutator{}

// DeploymentMutator is a handler modifying the resource definitions of the deployment targets
type DeploymentMutator struct {
	Client          client.Client
	Decoder         *webhook.AdmissionDecoder
	ImagePullSecret string
}

// Handle provides interface implementation for the DeploymentMutator
func (a *DeploymentMutator) Handle(ctx context.Context, req webhook.AdmissionRequest) webhook.AdmissionResponse {

	_log := log.FromContext(ctx)

	if a.Decoder == nil {
		return webhook.Errored(http.StatusInternalServerError,
			fmt.Errorf("decoder in the admission handler cannot be nil"))
	}

	deployment := &appsv1.Deployment{}
	if err := a.Decoder.Decode(req, deployment); err != nil {
		return webhook.Errored(http.StatusBadRequest, err)
	}

	_log.V(9).Info("handling admission request", "resourceVersion", deployment.GetResourceVersion(),
		"generation", deployment.GetGeneration())

	// Simply return it the deployment is not part of the described targets
	if !configuration.GetOIDCAppsControllerConfig().Match(deployment) {
		return webhook.Allowed("not a target")
	}

	// Simply return if it is a delete operation
	if !deployment.GetDeletionTimestamp().IsZero() {
		return webhook.Allowed("delete")
	}

	patch := deployment.DeepCopy()
	clientId := configuration.GetOIDCAppsControllerConfig().GetClientID(patch)
	issuerUrl := configuration.GetOIDCAppsControllerConfig().GetOidcIssuerUrl(patch)
	target := configuration.GetOIDCAppsControllerConfig().GetUpstreamTarget(patch)
	upstreamUrl := fetchUpstreamUrl(target, patch.Spec.Template.Spec)
	suffix := fetchTargetSuffix(patch)

	// Add the OIDC annotation to the deployment template
	addAnnotations(patch)

	// Add required labels to pod spec template
	addPodLabels(&patch.Spec.Template, nil)

	// Add the oauth2-proxy volume
	addSecretSourceVolume(
		oidc_apps_controller.Oauth2VolumeName,
		"oauth2-proxy-"+suffix,
		&patch.Spec.Template.Spec,
	)

	// Add the resource-attribute secret volume for the kube-rbac-proxy
	addProjectedSecretSourceVolume(
		oidc_apps_controller.KubeRbacProxyVolumeName,
		"resource-attributes-"+suffix,
		&patch.Spec.Template.Spec,
	)

	// Add an optional kubeconfig secret for the kube-rbac-proxy
	if shallAddKubeConfigSecretName(patch) {
		addProjectedSecretSourceVolume(
			oidc_apps_controller.KubeRbacProxyVolumeName,
			fetchKubconfigSecretName(suffix, patch),
			&patch.Spec.Template.Spec,
		)
	}

	// Add an optional oidc ca secret for the kube-rbac-proxy
	if shallAddOidcCaSecretName(patch) {
		addProjectedSecretSourceVolume(
			oidc_apps_controller.KubeRbacProxyVolumeName,
			fetchOidcCASecretName(suffix, patch),
			&patch.Spec.Template.Spec,
		)
	}

	// Add OIDC Apps init container to deployment.
	addInitContainer("oidc-init", &patch.Spec.Template.Spec, getInitContainer(issuerUrl))

	// Add the OAUTH2 proxy sidecar to the pod template
	addProxyContainer("oauth2-proxy", &patch.Spec.Template.Spec, getOIDCProxyContainer())

	// Add the kube-rbac-proxy sidecar to the pod template
	addProxyContainer("kube-rbac-proxy", &patch.Spec.Template.Spec, getKubeRbacProxyContainer(clientId, issuerUrl, upstreamUrl, patch))

	// Add image pull secret if the proxy container images are served from private registry
	if len(a.ImagePullSecret) > 0 {
		addImagePullSecret(a.ImagePullSecret, &patch.Spec.Template.Spec)
	}

	original, err := json.Marshal(deployment)
	if err != nil {
		_log.Info("Unable to marshal pod")
	}

	patched, err := json.Marshal(patch)
	if err != nil {
		_log.Info("Unable to marshal pod")
	}
	return admission.PatchResponseFromRaw(original, patched)
}
