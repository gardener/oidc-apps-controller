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
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
)

// Register the webhook with the server
var _ admission.Handler = &PodMutator{}

// PodMutator is a handler modifying the resource definitions of the pod targets
type PodMutator struct {
	Client          client.Client
	Decoder         webhook.AdmissionDecoder
	ImagePullSecret string
}

// Handle provides interface implementation for the PodMutator
func (p *PodMutator) Handle(ctx context.Context, req webhook.AdmissionRequest) webhook.AdmissionResponse {
	_log := log.FromContext(ctx)

	if p.Decoder == nil {
		return webhook.Errored(http.StatusInternalServerError,
			fmt.Errorf("decoder in the admission handler cannot be nil"))
	}

	pod := &corev1.Pod{}
	if err := p.Decoder.Decode(req, pod); err != nil {
		return webhook.Errored(http.StatusBadRequest, err)
	}

	// Simply return if it is a delete operation
	if !pod.GetDeletionTimestamp().IsZero() {
		return webhook.Allowed("delete")
	}

	// Simply return it the pod is not part of the described targets

	target, owner := isTarget(ctx, p.Client, pod)
	if !target {
		return webhook.Allowed("not a target")
	}

	_log.Info("handling pod admission request")

	patch := pod.DeepCopy()
	clientId := configuration.GetOIDCAppsControllerConfig().GetClientID(owner)
	issuerUrl := configuration.GetOIDCAppsControllerConfig().GetOidcIssuerUrl(owner)
	upstream := configuration.GetOIDCAppsControllerConfig().GetUpstreamTarget(owner)
	upstreamUrl := fetchUpstreamUrl(upstream, patch.Spec)
	suffix := fetchTargetSuffix(owner)

	// Add the OIDC annotation to the deployment template
	addAnnotations(patch)

	// Add required annotations to pod spec template
	addPodAnnotations(patch,
		map[string]string{
			constants.AnnotationHostKey: configuration.GetOIDCAppsControllerConfig().GetHost(owner),
		},
	)

	// Add required labels to pod spec template
	addPodLabels(patch,
		map[string]string{
			constants.LabelKey: "pod",
		},
	)

	// Add the oauth2-proxy volume
	addProjectedSecretSourceVolume(
		constants.Oauth2VolumeName,
		constants.SecretNameOauth2Proxy+"-"+suffix,
		&patch.Spec,
	)
	if shallAddOidcCaSecretName(owner) {
		addProjectedSecretSourceVolume(
			constants.Oauth2VolumeName,
			fetchOidcCASecretName(suffix, owner),
			&patch.Spec,
		)
	}

	// Add the resource-attribute secret volume for the kube-rbac-proxy
	addProjectedSecretSourceVolume(
		constants.KubeRbacProxyVolumeName,
		constants.SecretNameResourceAttributes+"-"+suffix,
		&patch.Spec,
	)

	// Add an optional kubeconfig secret for the kube-rbac-proxy
	if shallAddKubeConfigSecretName(owner) {
		addProjectedSecretSourceVolume(
			constants.KubeRbacProxyVolumeName,
			fetchKubconfigSecretName(suffix, owner),
			&patch.Spec,
		)
	}

	// Add an optional oidc ca secret for the kube-rbac-proxy
	if shallAddOidcCaSecretName(owner) {
		addProjectedSecretSourceVolume(
			constants.KubeRbacProxyVolumeName,
			fetchOidcCASecretName(suffix, owner),
			&patch.Spec,
		)
	}

	// Add the OAUTH2 proxy sidecar to the pod template
	addProxyContainer(constants.ContainerNameOauth2Proxy, &patch.Spec, getOIDCProxyContainer(&patch.Spec, owner))

	// Add the kube-rbac-proxy sidecar to the pod template
	addProxyContainer(constants.ContainerNameKubeRbacProxy, &patch.Spec, getKubeRbacProxyContainer(clientId,
		issuerUrl, upstreamUrl, patch, owner))

	// Add image pull secret if the proxy container images are served from private registry
	if len(p.ImagePullSecret) > 0 {
		addImagePullSecret(p.ImagePullSecret, &patch.Spec)
	}

	podIndex, present := patch.GetObjectMeta().GetLabels()["statefulset.kubernetes.io/pod-name"]
	if present {
		hostPrefix := configuration.GetOIDCAppsControllerConfig().GetHost(owner)
		host, domain, found := strings.Cut(hostPrefix, ".")
		if found {
			l := strings.Split(podIndex, "-")
			host = fmt.Sprintf("%s-%s.%s", host, l[len(l)-1], domain)
		}
		_log.Info(fmt.Sprintf("host: %s", host))

		for idx, container := range patch.Spec.Containers {
			if container.Name != "oauth2-proxy" {
				continue
			}
			// Remove the argument if present
			for i, arg := range container.Args {
				if strings.HasPrefix(arg, "--redirect-url") {
					patch.Spec.Containers[idx].Args = slices.Delete(patch.Spec.Containers[idx].Args, i, i+1)
				}
			}
			// Add the correct argument
			patch.Spec.Containers[idx].Args = append(patch.Spec.Containers[idx].Args,
				fmt.Sprintf("--redirect-url=https://%s/oauth2/callback", host),
			)

			break
		}
	}

	original, err := json.Marshal(pod)
	if err != nil {
		_log.Info("Unable to marshal pod")
	}

	patched, err := json.Marshal(patch)
	if err != nil {
		_log.Info("Unable to marshal pod")
	}

	return admission.PatchResponseFromRaw(original, patched)
}

func isTarget(ctx context.Context, c client.Client, pod *corev1.Pod) (bool, client.Object) {
	// Identify the workload
	owners := pod.GetOwnerReferences()
	if len(owners) == 0 {
		return false, nil
	}

	for _, o := range owners {
		if o.Kind == "StatefulSet" {
			statefulset := &appsv1.StatefulSet{}
			if err := c.Get(ctx, client.ObjectKey{Name: o.Name, Namespace: pod.GetNamespace()},
				statefulset); err != nil {
				log.FromContext(ctx).Error(err, "unable to get statefulset for object", "object", pod)

				return false, nil
			}

			return configuration.GetOIDCAppsControllerConfig().Match(statefulset), statefulset
		}

		if o.Kind == "ReplicaSet" {
			replicaset := &appsv1.ReplicaSet{}
			if err := c.Get(ctx, client.ObjectKey{Name: o.Name, Namespace: pod.GetNamespace()}, replicaset); err != nil {
				log.FromContext(ctx).Error(err, "unable to get replicaset for object", "object", pod)

				return false, nil
			}
			deployment := &appsv1.Deployment{}
			if err := c.Get(ctx, client.ObjectKey{Name: replicaset.GetOwnerReferences()[0].Name,
				Namespace: pod.GetNamespace()},
				deployment); err != nil {
				log.FromContext(ctx).Error(err, "unable to get deployment for object", "object", pod)

				return false, nil
			}

			return configuration.GetOIDCAppsControllerConfig().Match(deployment), deployment

		}
	}

	return false, nil
}
