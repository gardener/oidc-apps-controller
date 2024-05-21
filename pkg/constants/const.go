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

package constants

const (
	//AnnotationHostKey is the annotation key designating the target domain of the upstream workload
	AnnotationHostKey = "oidc-application-controller/host"
	//AnnotationTargetKey is the porotocl, port tuples of the upstream work; protocol=http, port=3000
	AnnotationTargetKey = "oidc-application-controller/target"
	//AnnotationKey depicts that the workload is enriched by the controller
	AnnotationKey = "oidc-application-controller/component"
	//AnnotationSuffixKey holds the name suffix of the mounted confguration secrets
	AnnotationSuffixKey = "oidc-application-controller/suffix"
	//AnnotationOauth2SecertCehcksumKey holds the checksum of the ouath2 proxy confguration secret
	AnnotationOauth2SecertCehcksumKey = "oidc-application-controller/oauth2-secret-checksum"
	//PodWebHookPath is the context path of the mutating webhook for pods
	PodWebHookPath = "/oidc-mutate-v1-pod"
	//VpaWebHookPath is the context path of the mutating webhook for pods
	VpaWebHookPath = "/oidc-mutate-v1-vpa"
	//NAMESPACE is the name of the required environment variable
	NAMESPACE = "NAMESPACE"

	//ContainerNameOidcInit is the name of the init container
	ContainerNameOidcInit = "oidc-init"
	//ContainerNameOauth2Proxy is the name of the oauth2-proxy container
	ContainerNameOauth2Proxy = "oauth2-proxy"
	//ContainerNameKubeRbacProxy is the name of the kube-rbac-proxy container
	ContainerNameKubeRbacProxy = "kube-rbac-proxy"
	//SecretNameOauth2Proxy is the name of the kube-rbac-proxy container
	SecretNameOauth2Proxy = "oauth2-proxy"
	//SecretNameResourceAttributes is the name of the resource attributes secret
	SecretNameResourceAttributes = "resource-attributes"
	//SecretNameKubeconfig is the name of the kubeconfig secret
	SecretNameKubeconfig = "kubeconfig"
	//SecretNameOidcCa is the name of the oidc ca secret
	SecretNameOidcCa = "oidc-ca"
	//ServiceNameOauth2Service is the name of the oauth2 service
	ServiceNameOauth2Service = "oauth2-service"
	//IngressName is the name of the oauth2 ingress
	IngressName = "oauth2-ingress"

	//LabelKey is the label added to dependent configuration secrets
	LabelKey = "oidc-application-controller/component"
	//LabelValue is the label added to dependent configuration secrets
	LabelValue = "oidc-apps"
	//SecretLabelKey is the label added to dependent configuration secrets
	SecretLabelKey = "oidc-application-controller/secret"
	//Oauth2LabelValue is the value of the Label
	Oauth2LabelValue = "oauth2"
	//RbacLabelValue is the value of the Label
	RbacLabelValue = "rbac"
	//OidcCa2LabelValue is the value of the Label
	OidcCa2LabelValue = "oidc-ca"
	//KubeconfigLabelValue is the value of the Label
	KubeconfigLabelValue = "kubeconfig"
	//RegistrySecretLabelValue is the value of the Label
	RegistrySecretLabelValue = "registry-secret"

	//GardenerPublicLabelsKey is a label used by the gardener network policy controller to manage access to public networks
	GardenerPublicLabelsKey = "networking.gardener.cloud/to-public-networks"
	//GardenerPrivateLabelsKey is aworkload label used by the gardener network policy controller to manage access to private networks
	GardenerPrivateLabelsKey = "networking.gardener.cloud/to-private-networks"

	//Oauth2VolumeName is the volume name of the oauth2-proxy configuration
	Oauth2VolumeName = "oauth2-proxy"
	//KubeRbacProxyVolumeName is the volume name of the kube-rbac-proxy configuration
	KubeRbacProxyVolumeName = "kube-rbac-proxy"

	//GARDEN_KUBECONFIG is an environment variable pointing at the default extension access token, if the custom one is not provided
	GARDEN_KUBECONFIG = "GARDEN_KUBECONFIG"
	//GARDEN_ACCESS_TOKEN is an environment variable pointing at a custom access token
	GARDEN_ACCESS_TOKEN = "GARDEN_ACCESS_TOKEN"
	//GARDEN_NAMESPACE is the default k8s namespace containing seed workloads
	GARDEN_NAMESPACE = "garden"
	//GARDEN_SEED_DOMAIN_NAME is the default domain name of the seed cluster, where the extension is running
	GARDEN_SEED_DOMAIN_NAME = "GARDEN_SEED_DOMAIN_NAME"
	//GARDEN_SEED_OAUTH2_PROXY_CLIENT_ID is the oidc clientId for the seed cluster, where the extension is running
	GARDEN_SEED_OAUTH2_PROXY_CLIENT_ID = "GARDEN_SEED_OAUTH2_PROXY_CLIENT_ID"
)
