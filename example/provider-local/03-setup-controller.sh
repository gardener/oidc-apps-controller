#!/usr/bin/env bash

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
type: helm
providerConfig:
  chart: $chart
  values:
    replicas: 1
    priorityClass:
      name: gardener-system-100
    clients:
      - name: local
        clientId: local
    image:
      repository: europe-docker.pkg.dev/gardener-project/snapshots/gardener/extensions/$controller_name
      tag: $version
    imagePullPolicy: Always
    webhook:
      namespaceSelector:
        matchExpressions:
          - {key: "shoot.gardener.cloud/no-cleanup", operator: "NotIn", values: ["true"]}
          - {key: "gardener.cloud/purpose", operator: "NotIn", values: ["kube-system"]}
          - {key: "kubernetes.io/metadata.name", operator: "NotIn", values: ["kube-system"]}
          - {key: "gardener.cloud/role", operator: "NotIn", values: ["extension"]}
      # TODO: Add the moment there is no single label key to identify the components which should be
      # enahnaced by the webhook. This setup is not recommended in production environments.
      # For production environments, there shall be a single key on pod level and each component
      # shall have it own value
      # objectSelector:
      #   matchExpressions:
      #     - {key: "gardener.cloud/role", operator: "In", values: ["plutono", "prometheus", ...]}
    vpa:
      enabled: true
    configuration:
      oauth2Proxy:
        sslInsecureSkipVerify: true
        insecureOidcSkipIssuerVerification: false
        oidcIssuerUrl: "https://dexidp:5556"
        scope: "openid email groups"
      kubeRbacProxy:
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
          hostPrefix: pl
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
          hostPrefix: pr
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
            app: prometheus
            name: seed
        targetPort: 9090
        ingress:
          create: true
          ingressClassName: "nginx-ingress-gardener"
          tlsSecretRef:
            name: "ingress-wildcard-cert"
            namespace: "garden"
      - name: "garden--aggregate-prometheus"
        namespaceSelector:
          matchLabels:
            project.gardener.cloud/name: garden
        labelSelector:
          matchLabels:
            app: aggregate-prometheus
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

charts_dir=$(realpath "$dir/../../charts/*")
for f in $charts_dir; do
    [[ -d "$f" ]] && generate_controller_registration $f;
done

kubectl apply -f "$dir/oidc-apps-controller-registration.yaml"
