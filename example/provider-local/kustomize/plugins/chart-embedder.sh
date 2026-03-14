#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Read the ResourceList from stdin
resourceList=$(cat)

# Extract configuration from functionConfig
chartsParentDir=$(echo "$resourceList" | yq e '.functionConfig.spec.chartsParentDir' -)
chartName=$(echo "$resourceList" | yq e '.functionConfig.spec.chartName' -)
caCertPath=$(echo "$resourceList" | yq e '.functionConfig.spec.caCertPath' -)

# Resolve paths relative to the kustomization directory (CWD set by kustomize)
chart=$(tar --sort=name -c --owner=root:0 --group=root:0 -C "$chartsParentDir" "$chartName" | gzip -n | base64 | tr -d '\n')
ca_bundle=$(base64 < "$caCertPath" | tr -d '\n')

# IMAGE_REPOSITORY and IMAGE_TAG are passed via environment from the Makefile
image_repository="${IMAGE_REPOSITORY:-europe-docker.pkg.dev/gardener-project/snapshots/gardener/extensions/oidc-apps-controller}"
image_tag="${IMAGE_TAG:-latest}"

cat <<EOF
kind: ResourceList
items:
- apiVersion: core.gardener.cloud/v1
  kind: ControllerDeployment
  metadata:
    name: oidc-apps-controller
  injectGardenKubeconfig: true
  helm:
    rawChart: $chart
    values:
      replicas: 1
      priorityClass:
        name: gardener-system-100
      image:
        repository: $image_repository
        tag: "$image_tag"
      imagePullPolicy: Always
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
      cacheSelectorStr: "observability.gardener.cloud/app in (plutono, prometheus-shoot, prometheus-cache, prometheus-aggregate, prometheus-seed, victoria-logs)"
      webhook:
        objectSelector:
          matchExpressions:
            - key: "observability.gardener.cloud/app"
              operator: "In"
              values: ["plutono", "prometheus-shoot", "prometheus-cache", "prometheus-aggregate", "prometheus-seed", "victoria-logs"]
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
            labels:
              endpoint.shoot.gardener.cloud/advertise: "true"
              endpoint.shoot.gardener.cloud/application: creadtiv--plutono
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
            labels:
              endpoint.shoot.gardener.cloud/advertise: "true"
              endpoint.shoot.gardener.cloud/application: prometheus--prometheus
        - name: "shoot--victoria-logs"
          namespaceSelector:
            matchLabels:
              gardener.cloud/role: shoot
          labelSelector:
            matchLabels:
              app.kubernetes.io/instance: victoria-logs
          targetPort: 9428
          ingress:
            labels:
              endpoint.shoot.gardener.cloud/advertise: "true"
              endpoint.shoot.gardener.cloud/application: victoriametrics--victoria-logs
            create: true
            defaultPath: "/select/vmui"
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
            labels:
              seed: plutono
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
        - name: "garden--victoria-logs"
          namespaceSelector:
            matchLabels:
              project.gardener.cloud/name: garden
          labelSelector:
            matchLabels:
              app.kubernetes.io/instance: victoria-logs
          targetPort: 9428
          ingress:
            create: true
            defaultPath: "/select/vmui"
            ingressClassName: "nginx-ingress-gardener"
            tlsSecretRef:
              name: "ingress-wildcard-cert"
              namespace: "garden"
EOF
