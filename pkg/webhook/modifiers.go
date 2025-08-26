// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/oidc-apps-controller/imagevector"
	"github.com/gardener/oidc-apps-controller/pkg/configuration"
	"github.com/gardener/oidc-apps-controller/pkg/constants"
	"github.com/gardener/oidc-apps-controller/pkg/rand"
)

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
	var cfg string

	extConfig := configuration.GetOIDCAppsControllerConfig()

	switch extConfig.GetClientSecret(object) {
	case "":
		cfg = configuration.NewOAuth2Config(
			configuration.WithClientID(extConfig.GetClientID(object)),
			configuration.WithClientSecretFile("/dev/null"),
			configuration.WithScope(extConfig.GetScope(object)),
			configuration.WithRedirectURL(extConfig.GetRedirectURL(object)),
			configuration.WithOidcIssuerURL(extConfig.GetOidcIssuerURL(object)),
			configuration.EnableSslInsecureSkipVerify(extConfig.GetSslInsecureSkipVerify(object)),
			configuration.EnableInsecureOidcSkipIssuerVerification(extConfig.GetInsecureOidcSkipIssuerVerification(object)),
			configuration.EnableInsecureOidcSkipNonce(extConfig.GetInsecureOidcSkipNonce(object)),
		).Parse()
	default:
		cfg = configuration.NewOAuth2Config(
			configuration.WithClientID(extConfig.GetClientID(object)),
			configuration.WithClientSecret(extConfig.GetClientSecret(object)),
			configuration.WithScope(extConfig.GetScope(object)),
			configuration.WithRedirectURL(extConfig.GetRedirectURL(object)),
			configuration.WithOidcIssuerURL(extConfig.GetOidcIssuerURL(object)),
			configuration.EnableSslInsecureSkipVerify(extConfig.GetSslInsecureSkipVerify(object)),
			configuration.EnableInsecureOidcSkipIssuerVerification(extConfig.GetInsecureOidcSkipIssuerVerification(object)),
			configuration.EnableInsecureOidcSkipNonce(extConfig.GetInsecureOidcSkipNonce(object)),
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
		// Items:    nil,
		Optional: ptr.To(false),
	}

	// Add the secret projected volume source in case there are no others
	if volume.Projected == nil {
		volume.Projected = &corev1.ProjectedVolumeSource{
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
	if len(volume.Projected.Sources) == 0 {
		volume.Projected.Sources = []corev1.VolumeProjection{
			{Secret: secret},
		}
		if appendVolume {
			podSpec.Volumes = append(podSpec.Volumes, volume)
		}

		return
	}

	// Replace the secret source in case the secret source is present
	for _, source := range volume.Projected.Sources {
		if source.Secret.Name == secretName {
			source.Secret = secret

			if appendVolume {
				podSpec.Volumes = append(podSpec.Volumes, volume)
			}

			return
		}
	}

	// Append the secret source in case the secret source is not present
	volume.Projected.Sources = append(volume.Projected.Sources,
		corev1.VolumeProjection{
			Secret: secret,
		},
	)

	if appendVolume {
		podSpec.Volumes = append(podSpec.Volumes, volume)
	}
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

func buildUpstreamURL(target string, podSpec corev1.PodSpec) string {
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

func getKubeRbacProxyContainer(clientID, issuerURL, upstream string, pod *corev1.Pod, owner client.Object) corev1.Container {
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
		Requests: map[corev1.ResourceName]resource.Quantity{
			"cpu":    resource.MustParse("5m"),
			"memory": resource.MustParse("32Mi"),
		},
	}

	for _, c := range pod.Spec.Containers {
		if c.Name != constants.ContainerNameKubeRbacProxy {
			continue
		}

		if !reflect.ValueOf(c.Resources.Requests).IsZero() {
			if c.Resources.Requests.Memory().Cmp(resource.MustParse("100Mi")) > 0 {
				containerResourceRequirements.Requests = c.Resources.Requests
			}
		}
	}

	container := corev1.Container{
		Name:            constants.ContainerNameKubeRbacProxy,
		Image:           image.String(),
		ImagePullPolicy: "IfNotPresent",
		Args: []string{"--insecure-listen-address=0.0.0.0:8100",
			"--oidc-clientID=" + clientID,
			"--oidc-issuer=" + issuerURL,
			"--upstream=" + upstream,
			"--config-file=/etc/kube-rbac-proxy/config-file.yaml"},
		Ports: []corev1.ContainerPort{
			{Name: "rbac", ContainerPort: 8100},
		},
		SecurityContext: &corev1.SecurityContext{
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			AllowPrivilegeEscalation: ptr.To(false),
			ReadOnlyRootFilesystem:   ptr.To(true),
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

func getOIDCProxyContainer(pod *corev1.PodSpec, owner client.Object) corev1.Container {
	image, _ := imagevector.ImageVector().FindImage("oauth2-proxy")

	if pod == nil {
		return corev1.Container{}
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      constants.Oauth2VolumeName,
			ReadOnly:  true,
			MountPath: "/etc/oauth2-proxy",
		},
	}

	containerResourceRequirements := corev1.ResourceRequirements{
		Requests: map[corev1.ResourceName]resource.Quantity{
			"cpu":    resource.MustParse("5m"),
			"memory": resource.MustParse("32Mi"),
		},
	}

	for _, c := range pod.Containers {
		if c.Name != constants.ContainerNameOauth2Proxy {
			continue
		}

		if !reflect.ValueOf(c.Resources.Requests).IsZero() {
			if c.Resources.Requests.Memory().Cmp(resource.MustParse("100Mi")) > 0 {
				containerResourceRequirements.Requests = c.Resources.Requests
			}
		}
	}

	container := corev1.Container{
		Name:            constants.ContainerNameOauth2Proxy,
		Image:           image.String(),
		ImagePullPolicy: "IfNotPresent",
		Args: []string{"--provider=oidc",
			"--config=/etc/oauth2-proxy/oauth2-proxy.cfg",
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
		SecurityContext: &corev1.SecurityContext{
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			AllowPrivilegeEscalation: ptr.To(false),
			ReadOnlyRootFilesystem:   ptr.To(true),
		},
		Ports: []corev1.ContainerPort{
			{Name: "oauth2", ContainerPort: 8000},
		},
		Resources:    containerResourceRequirements,
		VolumeMounts: volumeMounts,
	}

	if shallAddOidcCaSecretName(owner) {
		// Add volume mount and start parameter if the secret name is provided
		container.Args = append(container.Args, "--provider-ca-file=/etc/oauth2-proxy/ca.crt")
	}

	return container
}

func shallAddKubeConfigSecretName(object client.Object) bool {
	// There are potentially two sources of the kubeconfig:
	// 1. Global, meaning the kubeconfig secret reference is supplied with the oidc-apps-controller setup
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
