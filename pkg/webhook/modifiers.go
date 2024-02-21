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
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/gardener/oidc-apps-controller/imagevector"
	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
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
		annotations = make(map[string]string, 5)
	}
	annotations[constants.AnnotationKey] = object.GetName()
	annotations[constants.AnnotationHostKey] = configuration.GetOIDCAppsControllerConfig().GetHost(object)
	annotations[constants.AnnotationTargetKey] = configuration.GetOIDCAppsControllerConfig().GetUpstreamTarget(object)
	annotations[constants.AnnotationSuffixKey] = fetchTargetSuffix(object)
	annotations[constants.AnnotationOauth2SecertCehcksumKey] = get2ProxySecretChecksum(object)
	object.SetAnnotations(annotations)
}

func get2ProxySecretChecksum(object client.Object) string {
	extConfig := configuration.GetOIDCAppsControllerConfig()
	var cfg string
	switch extConfig.GetClientSecret(object) {
	case "":
		cfg = configuration.NewOAuth2Config(
			configuration.WithClientId(extConfig.GetClientID(object)),
			configuration.WithClientSecretFile("/dev/null"),
			configuration.WithScope(extConfig.GetScope(object)),
			configuration.WithRedirectUrl(extConfig.GetRedirectUrl(object)),
			configuration.WithOidcIssuerUrl(extConfig.GetOidcIssuerUrl(object)),
			configuration.EnableSslInsecureSkipVerify(extConfig.GetSslInsecureSkipVerify(object)),
			configuration.EnableInsecureOidcSkipIssuerVerification(extConfig.GetInsecureOidcSkipIssuerVerification(object)),
		).Parse()
	default:
		cfg = configuration.NewOAuth2Config(
			configuration.WithClientId(extConfig.GetClientID(object)),
			configuration.WithClientSecret(extConfig.GetClientSecret(object)),
			configuration.WithScope(extConfig.GetScope(object)),
			configuration.WithRedirectUrl(extConfig.GetRedirectUrl(object)),
			configuration.WithOidcIssuerUrl(extConfig.GetOidcIssuerUrl(object)),
			configuration.EnableSslInsecureSkipVerify(extConfig.GetSslInsecureSkipVerify(object)),
			configuration.EnableInsecureOidcSkipIssuerVerification(extConfig.GetInsecureOidcSkipIssuerVerification(object)),
		).Parse()
	}

	return rand.GenerateFullSha256(cfg)

}

// Add gardener specific labels to the target pods.
// Those are needed to construct the correct k8s network policies.
// TODO: add configurable labels in the helm chart
func addPodLabels(pod *corev1.Pod, lbls map[string]string) {
	labels := pod.GetLabels()
	if len(labels) == 0 {
		labels = make(map[string]string, 2)
	}
	labels[constants.GardenerPublicLabelsKey] = "allowed"
	labels[constants.GardenerPrivateLabelsKey] = "allowed"
	if len(lbls) == 0 {
		pod.SetLabels(labels)
		return
	}
	maps.Copy(labels, lbls)
	pod.SetLabels(labels)
}

func addPodAnnotations(pod *corev1.Pod, ann map[string]string) {
	annotations := pod.GetAnnotations()
	if len(annotations) == 0 {
		annotations = make(map[string]string, 1)
	}

	if len(ann) == 0 {
		pod.SetAnnotations(annotations)
		return
	}
	maps.Copy(annotations, ann)
	pod.SetAnnotations(annotations)
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
	appendVolume := true // Assume that there is no such volume
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
	return constants.SecretNameKubeconfig + "-" + suffix
}

func fetchOidcCASecretName(suffix string, object client.Object) string {
	if configuration.GetOIDCAppsControllerConfig().GetOidcCABundle(object) != "" {
		return constants.SecretNameOidcCa + "-" + suffix
	}

	return configuration.GetOIDCAppsControllerConfig().GetOidcCASecretName(object)
}

func fetchTargetSuffix(object client.Object) string {
	objectAnnotations := object.GetAnnotations()
	if len(objectAnnotations) == 0 {
		objectAnnotations = make(map[string]string, 1)
	}
	suffix, ok := objectAnnotations[constants.AnnotationSuffixKey]
	if !ok {
		suffix = rand.GenerateSha256(object.GetName() + "-" + object.GetNamespace())
		objectAnnotations[constants.AnnotationSuffixKey] = suffix
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
				Name:      constants.KubeRbacProxyVolumeName,
				ReadOnly:  true,
				MountPath: "/etc/kube-rbac-proxy",
			},
		},
	}
}

func getKubeRbacProxyContainer(clientID, issuerUrl, upstream string, pod *corev1.Pod, owner client.Object) corev1.Container {

	image, _ := imagevector.ImageVector().FindImage("kube-rbac-proxy-watcher")
	if pod == nil {
		return corev1.Container{}
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      constants.KubeRbacProxyVolumeName,
			ReadOnly:  true,
			MountPath: "/etc/kube-rbac-proxy",
		},
	}

	// Add the service account token volume mount
	for _, v := range pod.Spec.Volumes {
		if v.Projected != nil && v.Projected.Sources != nil {
			for _, s := range v.Projected.Sources {
				if s.ServiceAccountToken != nil {
					serviceAccountVolumeMount := corev1.VolumeMount{
						Name:      v.Name,
						ReadOnly:  true,
						MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
					}
					volumeMounts = append(volumeMounts, serviceAccountVolumeMount)
					break
				}
			}
		}
	}

	containerResourceRequirements := corev1.ResourceRequirements{
		Limits: map[corev1.ResourceName]resource.Quantity{
			"cpu":    resource.MustParse("100m"),
			"memory": resource.MustParse("100Mi"),
		},
		Requests: map[corev1.ResourceName]resource.Quantity{
			"cpu":    resource.MustParse("100m"),
			"memory": resource.MustParse("100Mi"),
		},
	}
	for _, c := range pod.Spec.Containers {
		if c.Name != constants.ContainerNameKubeRbacProxy {
			continue
		}
		if !reflect.ValueOf(c.Resources.Limits).IsZero() {
			containerResourceRequirements.Limits = c.Resources.Limits
		}
		if !reflect.ValueOf(c.Resources.Requests).IsZero() {
			containerResourceRequirements.Requests = c.Resources.Requests
		}
	}

	container := corev1.Container{
		Name:            constants.ContainerNameKubeRbacProxy,
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
		Resources:    containerResourceRequirements,
		VolumeMounts: volumeMounts,
	}

	if shallAddKubeConfigSecretName(owner) {
		// Add volume mount and start parameter if the secret name is provided
		container.Args = append(container.Args, "--kubeconfig=/etc/kube-rbac-proxy/kubeconfig")
	}

	// TODO: There is a bug https://github.com/brancz/kube-rbac-proxy/issues/259
	if shallAddOidcCaSecretName(owner) {
		// Add volume mount and start parameter if the secret name is provided
		container.Args = append(container.Args, "--oidc-ca-file=/etc/kube-rbac-proxy/ca.crt")
	}

	return container
}

func getOIDCProxyContainer(pod *corev1.PodSpec) corev1.Container {
	image, _ := imagevector.ImageVector().FindImage("oauth2-proxy")

	if pod == nil {
		return corev1.Container{}
	}

	containerResourceRequirements := corev1.ResourceRequirements{
		Limits: map[corev1.ResourceName]resource.Quantity{
			"cpu":    resource.MustParse("100m"),
			"memory": resource.MustParse("100Mi"),
		},
		Requests: map[corev1.ResourceName]resource.Quantity{
			"cpu":    resource.MustParse("100m"),
			"memory": resource.MustParse("100Mi"),
		},
	}
	for _, c := range pod.Containers {
		if c.Name != constants.ContainerNameOauth2Proxy {
			continue
		}
		if !reflect.ValueOf(c.Resources.Limits).IsZero() {
			containerResourceRequirements.Limits = c.Resources.Limits
		}
		if !reflect.ValueOf(c.Resources.Requests).IsZero() {
			containerResourceRequirements.Requests = c.Resources.Requests
		}
	}

	return corev1.Container{
		Name:            constants.ContainerNameOauth2Proxy,
		Image:           image.String(),
		ImagePullPolicy: "IfNotPresent",
		Args: []string{"--provider=oidc",
			"--config=/etc/oauth2-proxy.cfg",
			"--code-challenge-method=S256",
			"--pass-authorization-header=true",
			"--cookie-secret=" + rand.GenerateRandomString(16),
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
		Resources: containerResourceRequirements,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      constants.Oauth2VolumeName,
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
