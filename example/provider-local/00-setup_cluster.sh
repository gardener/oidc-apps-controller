#!/usr/bin/env bash

set -e
dir="$(dirname "$0")"

cat $KUBECONFIG | yq '.current-context' | grep -q "kind-gardener-local" || (echo "KUBECONFIG is not set to kind-gardener-local context" && exit 1)

kubectl apply -f ${dir}/../01-subjectaccessreviews-clusterrole.yaml
kubectl apply -f ${dir}/../02-observabilityapps-operator-rbac.yaml
kubectl apply -f ${dir}/../02-observabilityapps-projects-rbac.yaml

kubectl annotate seed local oidc-apps.extensions.gardener.cloud/client-name=local
