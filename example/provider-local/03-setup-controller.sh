#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
# SPDX-License-Identifier: Apache-2.0


set -e
dir="$(dirname "$0")"
version=${1:-$(cat $dir/../../VERSION)}

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
  local ca_bundle=$(cat $dir/certs/ca.pem | base64 -w0)

cat <<EOF | tee "$dir/oidc-apps-controller-registration.yaml" >/dev/null 2>&1
---
apiVersion: core.gardener.cloud/v1beta1
kind: ControllerDeployment
metadata:
  name: $controller_name
injectGardenKubeconfig: true
type: helm
providerConfig:
  chart: $chart
  values:
    replicas: 1
    priorityClass:
      name: gardener-system-100
    image:
      repository: europe-docker.pkg.dev/gardener-project/snapshots/gardener/extensions/$controller_name
      tag: $version
    imagePullPolicy: Always
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
    cacheSelectorStr: "observability.gardener.cloud/app in (plutono, prometheus-shoot, prometheus-cache, prometheus-aggregate, prometheus-seed)"
    webhook:
      objectSelector:
        matchExpressions:
          - key: "observability.gardener.cloud/app"
            operator: "In"
            values: ["plutono", "prometheus-shoot", "prometheus-cache", "prometheus-aggregate", "prometheus-seed"]
    vpa:
      enabled: true
    clients:
      - name: local
        clientId: local
    global:
      oauth2Proxy:
        sslInsecureSkipVerify: false
        insecureOidcSkipIssuerVerification: false
        insecureOidcSkipNonce: false
        oidcIssuerUrl: "https://dexidp:5556"
        scope: "openid email groups"
      oidcCABundle: $ca_bundle
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
      - name: "garden--plutono"
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
      - name: "garden--prometheus-seed"
        namespaceSelector:
          matchLabels:
            project.gardener.cloud/name: garden
        labelSelector:
          matchLabels:
            name: seed
            role: monitoring
        targetPort: 9090
        ingress:
          create: true
          ingressClassName: "nginx-ingress-gardener"
          tlsSecretRef:
            name: "ingress-wildcard-cert"
            namespace: "garden"
      - name: "garden--prometheus-aggregate"
        namespaceSelector:
          matchLabels:
            project.gardener.cloud/name: garden
        labelSelector:
          matchLabels:
            name: aggregate
            role: monitoring
        targetPort: 9090
        ingress:
          create: true
          ingressClassName: "nginx-ingress-gardener"
          tlsSecretRef:
            name: "ingress-wildcard-cert"
            namespace: "garden"
      - name: "garden--prometheus-cache"
        namespaceSelector:
          matchLabels:
            project.gardener.cloud/name: garden
        labelSelector:
          matchLabels:
            name: cache
            role: monitoring
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

charts_dir=$(realpath "$dir/../../charts/*")
for f in $charts_dir; do
    [[ -d "$f" ]] && generate_controller_registration $f;
done

kubectl apply -f "$dir/oidc-apps-controller-registration.yaml"
