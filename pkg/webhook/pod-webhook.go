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

	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/constants"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Register the webhook with the server
var _ admission.Handler = &PodMutator{}

// PodMutator is a handler modifying the resource definitions of the pod targets
type PodMutator struct {
	Client  client.Client
	Decoder *webhook.AdmissionDecoder
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

	_log.V(9).Info("handling admission request", "resourceVersion", pod.GetResourceVersion(),
		"generation", pod.GetGeneration())

	// Simply return if it is a delete operation
	if !pod.GetDeletionTimestamp().IsZero() {
		return webhook.Allowed("delete")
	}

	patch := pod.DeepCopy()

	hostPrefix, ok := patch.GetAnnotations()[oidc_apps_controller.AnnotationHostKey]
	if !ok {
		return webhook.Errored(http.StatusBadRequest, fmt.Errorf("cannot find host annotation"))
	}
	host, domain, found := strings.Cut(hostPrefix, ".")
	if found {
		// In some envorinments, the pod index is added as a label: apps.kubernetes.io/pod-index
		podIndex, present := patch.GetObjectMeta().GetLabels()["statefulset.kubernetes.io/pod-name"]
		if present {
			l := strings.Split(podIndex, "-")
			host = fmt.Sprintf("%s-%s.%s", host, l[len(l)-1], domain)
		} else {

			host = fmt.Sprintf("%s.%s", host, domain)
		}
	}
	_log.Info(fmt.Sprintf("host: %s", host))

	for idx, container := range patch.Spec.Containers {
		if container.Name != "oauth2-proxy" {
			continue
		}
		// Remove the argument if present
		for i, arg := range container.Args {
			if strings.HasPrefix(arg, "--redirect-url") {
				slices.Delete(patch.Spec.Containers[idx].Args, i, i+1)
			}
		}
		// Add the correct argument
		patch.Spec.Containers[idx].Args = append(patch.Spec.Containers[idx].Args,
			fmt.Sprintf("--redirect-url=https://%s/oauth2/callback", host),
		)
		break
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
