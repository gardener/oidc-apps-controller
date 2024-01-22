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
	_ "embed"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/gardener/oidc-apps-controller/imagevector"
	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	oidc_apps_controller "github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/rand"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

//go:embed oidc-check.sh
var oidcInitCheck string

// Add an annotation to target workload.
func addAnnotations(object client.Object) {
	annotations := object.GetAnnotations()
	if len(annotations) == 0 {
		annotations = make(map[string]string, 2)
	}
	annotations[oidc_apps_controller.AnnotationKey] = object.GetName()
	annotations[oidc_apps_controller.AnnotationHostKey] = configuration.GetOIDCAppsControllerConfig().GetHost(object)
	annotations[oidc_apps_controller.AnnotationTargetKey] = configuration.GetOIDCAppsControllerConfig().GetUpstreamTarget(object)
	object.SetAnnotations(annotations)
}

// Add gardener specific labels to the target pods.
// Those are needed to construct the correct k8s network policies.
// TODO: add configurable labels in the helm chart
func addPodLabels(object *corev1.PodTemplateSpec, lbls map[string]string) {
	labels := object.GetLabels()
	if len(labels) == 0 {
		labels = make(map[string]string, 2)
	}
	labels[oidc_apps_controller.GardenerPublicLabelsKey] = "allowed"
	labels[oidc_apps_controller.GardenerPrivateLabelsKey] = "allowed"
	if len(lbls) == 0 {
		object.SetLabels(labels)
		return
	}
	maps.Copy(labels, lbls)
	object.SetLabels(labels)
}

func addPodAnnotations(object *corev1.PodTemplateSpec, ann map[string]string) {
	annotations := object.GetAnnotations()
	if len(annotations) == 0 {
		annotations = make(map[string]string, 1)
	}

	if len(ann) == 0 {
		object.SetAnnotations(annotations)
		return
	}
	maps.Copy(annotations, ann)
	object.SetAnnotations(annotations)
}

func addImagePullSecret(secretName string, podSpec *corev1.PodSpec) {
	if secretName == "" {
		return
	}

	if len(podSpec.ImagePullSecrets) == 0 {
		podSpec.ImagePullSecrets = []corev1.LocalObjectReference{
			{Name: secretName},
		}
		return
	}
	// Check to see if it is present
	for _, s := range podSpec.ImagePullSecrets {
		if s.Name == secretName {
			// Found no need to add
			return
		}
	}
	// Append the image pull secret
	podSpec.ImagePullSecrets = append(podSpec.ImagePullSecrets,
		corev1.LocalObjectReference{
			Name: secretName,
		},
	)
}

// Add secret source volume to the target pods.
func addSecretSourceVolume(name, secretName string, podSpec *corev1.PodSpec) {
	// Remove if present and later recreate appropriately
	volumes := podSpec.Volumes
	for i, v := range volumes {
		if v.Name == name {
			volumes = slices.Delete(volumes, i, i+1)
			break
		}
	}

	// Add the volume
	volumes = append(
		volumes,
		corev1.Volume{
			Name: name,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: secretName,
					Optional:   ptr.To(false),
				},
			},
		},
	)
	podSpec.Volumes = volumes
}

func addProjectedSecretSourceVolume(volumeName, secretName string, podSpec *corev1.PodSpec) {
	volume := corev1.Volume{Name: volumeName}
	appendVolume := true // Assume that there ase no such volume
	for i, v := range podSpec.Volumes {
		if v.Name == volumeName {
			volume = podSpec.Volumes[i] // Fetch the volume if it is present
			appendVolume = false
			break
		}
	}

	// Construct the secretProjection
	secret := &corev1.SecretProjection{
		LocalObjectReference: corev1.LocalObjectReference{
			Name: secretName,
		},
		//Items:    nil,
		Optional: ptr.To(false),
	}

	// Add the secret projected volume source in case there are no others
	if volume.VolumeSource.Projected == nil {
		volume.VolumeSource.Projected = &corev1.ProjectedVolumeSource{
			Sources: []corev1.VolumeProjection{
				{Secret: secret},
			},
		}
		if appendVolume {
			podSpec.Volumes = append(podSpec.Volumes, volume)
		}
		return
	}

	// Add the secret source in case there are no other sources in the projected volume
	if len(volume.VolumeSource.Projected.Sources) == 0 {
		volume.VolumeSource.Projected.Sources = []corev1.VolumeProjection{
			{Secret: secret},
		}
		if appendVolume {
			podSpec.Volumes = append(podSpec.Volumes, volume)
		}
		return
	}

	// Replace the secret source in case the secret source is present
	for _, source := range volume.VolumeSource.Projected.Sources {
		if source.Secret.Name == secretName {
			source.Secret = secret
			if appendVolume {
				podSpec.Volumes = append(podSpec.Volumes, volume)
			}
			return
		}
	}

	// Append the secret source in case the secret source is not present
	volume.VolumeSource.Projected.Sources = append(volume.VolumeSource.Projected.Sources,
		corev1.VolumeProjection{
			Secret: secret,
		},
	)

	if appendVolume {
		podSpec.Volumes = append(podSpec.Volumes, volume)
	}

}

func addInitContainer(name string, podSpec *corev1.PodSpec, container corev1.Container) {
	containers := podSpec.InitContainers
	for i, c := range containers {
		if c.Name == name {
			podSpec.InitContainers = slices.Delete(podSpec.InitContainers, i, i+1)
			break
		}
	}

	podSpec.InitContainers = append(podSpec.InitContainers, container)
}

func addProxyContainer(name string, podSpec *corev1.PodSpec, container corev1.Container) {
	containers := podSpec.Containers
	for i, c := range containers {
		if c.Name == name {
			podSpec.Containers = slices.Delete(podSpec.Containers, i, i+1)
			break
		}
	}

	podSpec.Containers = append(podSpec.Containers, container)
}

func fetchKubconfigSecretName(suffix string, object client.Object) string {
	if configuration.GetOIDCAppsControllerConfig().GetKubeConfigStr(object) != "" {
		return "kubeconfig-" + suffix
	}

	if configuration.GetOIDCAppsControllerConfig().GetKubeSecretName(object) != "" {
		return configuration.GetOIDCAppsControllerConfig().GetKubeSecretName(object)
	}

	// In case of gardener mounted kubeconfig, the name of the secret is as below
	return "kubeconfig-" + suffix
}

func fetchOidcCASecretName(suffix string, object client.Object) string {
	if configuration.GetOIDCAppsControllerConfig().GetOidcCABundle(object) != "" {
		return "oidcca-" + suffix
	}

	return configuration.GetOIDCAppsControllerConfig().GetOidcCASecretName(object)
}

func fetchTargetSuffix(object client.Object) string {
	objectAnnotations := object.GetAnnotations()
	if len(objectAnnotations) == 0 {
		objectAnnotations = make(map[string]string, 1)
	}
	suffix, ok := objectAnnotations[oidc_apps_controller.AnnotationSuffixKey]
	if !ok {
		suffix = rand.GenerateSha256(object.GetName() + "-" + object.GetNamespace())
		objectAnnotations[oidc_apps_controller.AnnotationSuffixKey] = suffix
		object.SetAnnotations(objectAnnotations)
	}
	return suffix
}

func fetchUpstreamUrl(target string, podSpec corev1.PodSpec) string {
	before, after, _ := strings.Cut(target, ",")
	protocol, f := strings.CutPrefix(before, "protocol=")
	if !f {
		protocol = "http"
	}
	port, _ := strings.CutPrefix(after, " port=")

	if len(port) == 0 {
		return protocol + "://localhost"
	}

	_, err := strconv.Atoi(port)
	if err == nil {
		return protocol + "://localhost" + ":" + port
	}

	// It is a named port shall iterate over the container ports
	for _, container := range podSpec.Containers {
		for _, p := range container.Ports {
			if p.Name == port {
				return protocol + "://localhost" + ":" + strconv.Itoa(int(p.ContainerPort))
			}
		}
	}
	return ""
}

func getInitContainer(oidcIssuerUrl string) corev1.Container {

	image, _ := imagevector.ImageVector().FindImage("curl-container")

	return corev1.Container{
		Name:            "oidc-init",
		Image:           image.String(),
		ImagePullPolicy: "IfNotPresent",
		Command:         []string{"sh", "-c"},
		Env: []corev1.EnvVar{
			{
				Name:  "OIDC_URL",
				Value: oidcIssuerUrl,
			},
		},
		Args: []string{oidcInitCheck},
		Resources: corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				"cpu":    resource.MustParse("10m"),
				"memory": resource.MustParse("50Mi"),
			},
			Requests: map[corev1.ResourceName]resource.Quantity{
				"cpu":    resource.MustParse("10m"),
				"memory": resource.MustParse("50Mi"),
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      oidc_apps_controller.KubeRbacProxyVolumeName,
				ReadOnly:  true,
				MountPath: "/etc/kube-rbac-proxy",
			},
		},
	}
}

func getKubeRbacProxyContainer(clientID, issuerUrl, upstream string, target client.Object) corev1.Container {

	image, _ := imagevector.ImageVector().FindImage("kube-rbac-proxy-watcher")

	container := corev1.Container{
		Name:            "kube-rbac-proxy",
		Image:           image.String(),
		ImagePullPolicy: "IfNotPresent",
		Args: []string{"--insecure-listen-address=0.0.0.0:8100",
			"--oidc-clientID=" + clientID,
			"--oidc-issuer=" + issuerUrl,
			"--upstream=" + upstream,
			"--config-file=/etc/kube-rbac-proxy/config-file.yaml",
			"--v=10"},
		Ports: []corev1.ContainerPort{
			{Name: "rbac", ContainerPort: 8100},
		},
		Resources: corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				"cpu":    resource.MustParse("100m"),
				"memory": resource.MustParse("100Mi"),
			},
			Requests: map[corev1.ResourceName]resource.Quantity{
				"cpu":    resource.MustParse("100m"),
				"memory": resource.MustParse("50Mi"),
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      oidc_apps_controller.KubeRbacProxyVolumeName,
				ReadOnly:  true,
				MountPath: "/etc/kube-rbac-proxy",
			},
		},
	}

	if shallAddKubeConfigSecretName(target) {
		// Add volume mount and start parameter if the secret name is provided
		container.Args = append(container.Args, "--kubeconfig=/etc/kube-rbac-proxy/kubeconfig")
	}

	// TODO: There is a bug https://github.com/brancz/kube-rbac-proxy/issues/259
	if shallAddOidcCaSecretName(target) {
		// Add volume mount and start parameter if the secret name is provided
		container.Args = append(container.Args, "--oidc-ca-file=/etc/kube-rbac-proxy/ca.crt")
	}

	return container
}

func getOIDCProxyContainer() corev1.Container {
	image, _ := imagevector.ImageVector().FindImage("oauth2-proxy")

	return corev1.Container{
		Name:            "oauth2-proxy",
		Image:           image.String(),
		ImagePullPolicy: "IfNotPresent",
		Args: []string{"--provider=oidc",
			"--config=/etc/oauth2-proxy.cfg",
			"--code-challenge-method=S256",
			"--pass-authorization-header=true",
			"--cookie-secret=73e4-1d15-4106-9",
			"--cookie-refresh=3600s",
			"--http-address=0.0.0.0:8000",
			"--email-domain=*",
			"--reverse-proxy=true",
			"--skip-provider-button=true",
			"--skip-jwt-bearer-tokens=true",
			"--upstream=http://127.0.0.1:8100"},
		Ports: []corev1.ContainerPort{
			{Name: "oauth2", ContainerPort: 8000},
		},
		Resources: corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				"cpu":    resource.MustParse("100m"),
				"memory": resource.MustParse("100Mi"),
			},
			Requests: map[corev1.ResourceName]resource.Quantity{
				"cpu":    resource.MustParse("100m"),
				"memory": resource.MustParse("50Mi"),
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      oidc_apps_controller.Oauth2VolumeName,
				ReadOnly:  true,
				MountPath: "/etc/oauth2-proxy.cfg",
				SubPath:   "oauth2-proxy.cfg",
			},
		},
	}
}

func shallAddKubeConfigSecretName(object client.Object) bool {

	// There are potentially two sources of the kubeconfig:
	// 1. Configuration, meaning the kubeconfig secret reference is supplied with the oidc-apps-controller setup
	// 2. The controller is running as a gardener extension, meaning that there is a mounted secret in the controller pod.
	// If either of these is missing the kube-rbac-proxy sidecar will be started without --kubeconfig setting using
	// the pod service account to creat the SubjectAccessReview requests

	if configuration.GetOIDCAppsControllerConfig().GetKubeConfigStr(object) != "" {
		return true
	}

	if configuration.GetOIDCAppsControllerConfig().GetKubeSecretName(object) != "" {
		return true
	}
	d := filepath.Dir(os.Getenv("GARDEN_KUBECONFIG"))
	if _, err := os.Stat(filepath.Join(d, "kubeconfig")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(d, "token")); err != nil {
		return false
	}

	return true
}

func shallAddOidcCaSecretName(object client.Object) bool {
	if configuration.GetOIDCAppsControllerConfig().GetOidcCABundle(object) != "" {
		return true
	}
	return configuration.GetOIDCAppsControllerConfig().GetOidcCASecretName(object) != ""
}
