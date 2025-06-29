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
	"errors"
	"net/http"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	"k8s.io/apimachinery/pkg/util/json"
	autoscalerv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
)

// Register the webhook with the server
var _ admission.Handler = &VPAMutator{}

// VPAMutator is a handler modifying the resource definitions of the vpa targets
type VPAMutator struct {
	Client  client.Client
	Decoder webhook.AdmissionDecoder
}

// Handle provides interface implementation for the PodMutator
func (v *VPAMutator) Handle(ctx context.Context, req webhook.AdmissionRequest) webhook.AdmissionResponse {
	_log := log.FromContext(ctx)

	if v.Decoder == nil {
		return webhook.Errored(http.StatusInternalServerError,
			errors.New("decoder in the admission handler cannot be nil"))
	}

	vpa := &autoscalerv1.VerticalPodAutoscaler{}
	if err := v.Decoder.Decode(req, vpa); err != nil {
		return webhook.Errored(http.StatusBadRequest, err)
	}

	// Check if VPA target ref
	if vpa.Spec.TargetRef == nil {
		return webhook.Allowed("vpa does not have a target ref")
	}

	if !configuration.GetOIDCAppsControllerConfig().Match(vpa) {
		if !isTargetRefMatched(ctx, v.Client, vpa.GetNamespace(), vpa.Spec.TargetRef) {
			return webhook.Allowed("vpa not matched")
		}
	}

	_log.Info("handling vpa admission request")

	// Simply return if it is a delete operation
	if !vpa.GetDeletionTimestamp().IsZero() {
		return webhook.Allowed("delete")
	}

	patch := vpa.DeepCopy()
	policies := make([]autoscalerv1.ContainerResourcePolicy, 0)

	for i, policy := range patch.Spec.ResourcePolicy.ContainerPolicies {
		if policy.ContainerName != constants.ContainerNameOauth2Proxy &&
			policy.ContainerName != constants.ContainerNameKubeRbacProxy {
			policies = append(policies, patch.Spec.ResourcePolicy.ContainerPolicies[i])
		}
	}

	policies = append(policies, autoscalerv1.ContainerResourcePolicy{
		ContainerName: constants.ContainerNameOauth2Proxy,
		Mode:          ptr.To(autoscalerv1.ContainerScalingModeOff),
	})
	policies = append(policies, autoscalerv1.ContainerResourcePolicy{
		ContainerName: constants.ContainerNameKubeRbacProxy,
		Mode:          ptr.To(autoscalerv1.ContainerScalingModeOff),
	})

	patch.Spec.ResourcePolicy.ContainerPolicies = policies

	original, err := json.Marshal(vpa)
	if err != nil {
		_log.Info("Unable to marshal vpa")
	}

	patched, err := json.Marshal(patch)
	if err != nil {
		_log.Info("Unable to marshal vpa")
	}

	return admission.PatchResponseFromRaw(original, patched)
}

func isTargetRefMatched(ctx context.Context, c client.Client, namespace string, ref *autoscalingv1.CrossVersionObjectReference) bool {
	switch ref.Kind {
	case "Deployment":
		deployment := &appsv1.Deployment{}
		if err := c.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: namespace}, deployment); err != nil {
			log.FromContext(ctx).V(9).Info("unable to get deployment", "name", ref.Name)

			return false
		}

		return configuration.GetOIDCAppsControllerConfig().Match(deployment)

	case "StatefulSet":
		statefulset := &appsv1.StatefulSet{}
		if err := c.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: namespace}, statefulset); err != nil {
			log.FromContext(ctx).V(9).Info("unable to get statefulset", "name", ref.Name)

			return false
		}

		return configuration.GetOIDCAppsControllerConfig().Match(statefulset)
	}

	return false
}
