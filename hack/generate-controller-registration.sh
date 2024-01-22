#!/usr/bin/env bash

set -o errexit
set -o functrace

dir=$(dirname $0)
version=${1:-$(cat $dir/../VERSION)}

function __catch() {
  local cmd="${1:-}"
  echo
  echo "errexit $cmd on line $(caller)" >&2
}
trap '__catch "${BASH_COMMAND}"' ERR

function generate_controller_registration() {
  local path=$1
  local controller_name=$(yq -r .name "${path}/Chart.yaml")
  local chart=$(tar --sort=name -c --owner=root:0 --group=root:0 -C "$path/.." "$controller_name" | gzip -n | base64 -w0)

cat <<EOF | tee "$dir/../example/controller-registration.yaml" >/dev/null 2>&1
---
apiVersion: core.gardener.cloud/v1beta1
kind: ControllerDeployment
metadata:
  name: $controller_name
type: helm
providerConfig:
  chart: $chart
  values:
    image:
      repository: europe-docker.pkg.dev/gardener-project/snapshots/gardener/extensions/$controller_name
      tag: $version
    imagePullSecrets:
      - name: gardener-images
    webhook:
      namespaceSelector:
        matchExpressions:
          - {key: "gardener.cloud/role", operator: "In", values: ["shoot","project"]}
          - {key: "shoot.gardener.cloud/no-cleanup", operator: "NotIn", values: ["true"]}
          - {key: "gardener.cloud/purpose", operator: "NotIn", values: ["kube-system"]}
          - {key: "kubernetes.io/metadata.name", operator: "NotIn", values: ["kube-system"]}
    vpa:
      enabled: true
    configuration:
      domainName: "... cluster domain ..." #cluster domain
      oauth2Proxy:
        sslInsecureSkipVerify: true
        insecureOidcSkipIssuerVerification: false
        oidcIssuerUrl: "... OIDC issuer URL ..."
        clientId: "... OIDC client ID ..."
        scope: "openid email groups"
      kubeRbacProxy:
        oidcCABundle: |
          -----BEGIN CERTIFICATE-----
          ...
          -----END CERTIFICATE-----
    targets:
      - name: "shoot--plutono"
        namespaceSelector:
          matchLabels:
            gardener.cloud/role: shoot
        labelSelector:
          matchLabels:
            component: plutono
        targetPort: 3000
        ingress:
          create: true
          ingressClassName: "nginx-ingress-gardener"
          tlsSecretRef:
            name: "ingress-wildcard-cert"
      - name: "shoot--prometheus"
        namespaceSelector:
          matchLabels:
            gardener.cloud/role: shoot
        labelSelector:
          matchLabels:
            app: prometheus
        targetPort: 9090
        ingress:
          create: true
          ingressClassName: "nginx-ingress-gardener"
          tlsSecretRef:
            name: "ingress-wildcard-cert"
      - name: "garden-plutono"
        namespaceSelector:
          matchLabels:
            project.gardener.cloud/name: garden
        labelSelector:
          matchLabels:
            component: plutono
        targetPort: 3000
        ingress:
          create: true
          ingressClassName: "nginx-ingress-gardener"
          tlsSecretRef:
            name: "ingress-wildcard-cert"
            namespace: "garden"
      - name: "garden-prometheus"
        namespaceSelector:
          matchLabels:
            project.gardener.cloud/name: garden
        labelSelector:
          matchLabels:
            app: prometheus
        targetPort: 9090
        ingress:
          create: true
          ingressClassName: "nginx-ingress-gardener"
          tlsSecretRef:
            name: "ingress-wildcard-cert"
            namespace: "garden"
---
apiVersion: core.gardener.cloud/v1beta1
kind: ControllerRegistration
metadata:
  name: $controller_name
  annotations:
    security.gardener.cloud/pod-security-enforce: baseline
spec:
  deployment:
    deploymentRefs:
    - name: "$controller_name"
    policy: Always
---
EOF

echo "Generated controller registration for $controller_name, version $version"

}

charts_dir=$(realpath "$dir/../charts/*")
for f in $charts_dir; do
    [[ -d "$f" ]] && generate_controller_registration $f;
done
