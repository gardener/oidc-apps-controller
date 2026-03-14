#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
# SPDX-License-Identifier: Apache-2.0

set -e
dir="$(dirname "$0")"
failed=0

function pass { printf '\u2714 %s\n' "$1"; }
function fail { printf '\u274c %s\n' "$1"; failed=1; }
function info { printf '  %s\n' "$1"; }

# --- Required commands ---
echo "--- Required commands ---"
for cmd in cfssl cfssljson jq docker kubectl curl kustomize yq kind; do
    if command -v "$cmd" &> /dev/null; then
        pass "$cmd found"
    else
        fail "$cmd not found"
    fi
done

for cmd in openssl ldapsearch slappasswd; do
    if command -v "$cmd" &> /dev/null; then
        pass "optional command \"$cmd\" found"
    else
        info "optional command \"$cmd\" not found"
    fi
done

# --- LDAP configuration ---
echo "--- LDAP configuration ---"
if [[ -f "$dir/configs/local.ldif" ]]; then
    if grep -q 'userpassword: # TODO: Add' "$dir/configs/local.ldif"; then
        fail "local.ldif has unset userpassword"
    else
        pass "local.ldif has userpassword set"
    fi
else
    info "local.ldif not found (will be generated on deploy)"
fi

# --- Docker network ---
echo "--- Docker network ---"
if docker network ls --format '{{.Name}}' | grep -q kind; then
    pass "\"kind\" network found"
else
    fail "\"kind\" network not found"
fi

if docker network inspect kind -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | grep -q '172.18.0.0'; then
    pass "kind subnet found"
else
    fail "kind subnet not found"
fi

if docker network inspect kind -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | grep -q 'gardener-local-control-plane'; then
    pass "gardener-local-control-plane found in kind network"
else
    fail "gardener-local-control-plane not found in kind network"
fi

# --- Dex and LDAP ---
echo "--- Dex and LDAP ---"
if docker inspect dexidp --format '{{.State.Running}}' 2>/dev/null | grep -q true; then
    pass "dexidp is running"
else
    fail "dexidp is not running"
fi

if docker inspect ldap --format '{{.State.Running}}' 2>/dev/null | grep -q true; then
    pass "ldap is running"
else
    fail "ldap is not running"
fi

if [[ -f "$dir/certs/ca.pem" ]]; then
    response=$(curl --cacert "$dir/certs/ca.pem" -s -o /dev/null -w '%{http_code}' \
        --max-time 5 "https://dexidp:5556/.well-known/openid-configuration" 2>/dev/null || echo "000")
    if [[ "$response" == "200" ]]; then
        pass "Dex .well-known/openid-configuration endpoint is up"
    else
        fail "Dex .well-known/openid-configuration endpoint is down (HTTP $response)"
    fi
else
    info "skipping Dex endpoint check (no CA cert)"
fi

if [[ -n "${LDAPSEARCH:-}" ]] || command -v ldapsearch &> /dev/null; then
    echo
    info "ldap records:"
    echo
    ldapsearch -LLL -H ldap://localhost:389 -x -D "cn=readonly,dc=local" -w "readonly" \
        -b "ou=Groups,dc=local" "objectClass=groupOfNames" 2>/dev/null || info "ldapsearch failed"
fi

# --- Kubernetes context ---
echo "--- Kubernetes context ---"
ctx=$(kubectl config current-context 2>/dev/null || echo "")
if echo "$ctx" | grep -q 'kind-gardener-local'; then
    pass "kubectl context is kind-gardener-local"
else
    fail "kubectl context is \"$ctx\", expected kind-gardener-local"
fi

# --- Gardener resources ---
echo "--- Gardener resources ---"
if kubectl get shoot local -n garden-local > /dev/null 2>&1; then
    pass "shoot \"local\" found in garden-local"
else
    fail "shoot \"local\" not found in garden-local"
fi

annotations=$(kubectl get seed -o jsonpath='{.items[].metadata.annotations}' 2>/dev/null || echo "")
if echo "$annotations" | grep -q 'oidc-apps.extensions.gardener.cloud/client-name'; then
    pass "seed annotation oidc-apps.extensions.gardener.cloud/client-name found"
else
    fail "seed annotation oidc-apps.extensions.gardener.cloud/client-name not found"
fi

roles=$(kubectl get clusterrole -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
for role in oidc-apps-subjectaccessreviews gardener.cloud:system:observabilityapps-operators gardener.cloud:system:observabilityapps-projects; do
    if echo "$roles" | grep -q "$role"; then
        pass "clusterrole \"$role\" found"
    else
        fail "clusterrole \"$role\" not found"
    fi
done

bindings=$(kubectl get clusterrolebinding -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
if echo "$bindings" | grep -q 'gardener.cloud:system:observabilityapps-operators'; then
    pass "clusterrolebinding \"gardener.cloud:system:observabilityapps-operators\" found"
else
    fail "clusterrolebinding \"gardener.cloud:system:observabilityapps-operators\" not found"
fi

# --- /etc/hosts ---
echo "--- /etc/hosts ---"
records=(
    dexidp
    plutono-garden.ingress.local.seed.local.gardener.cloud
    prometheus-seed-garden-0.ingress.local.seed.local.gardener.cloud
    prometheus-aggregate-garden-0.ingress.local.seed.local.gardener.cloud
    prometheus-cache-garden-0.ingress.local.seed.local.gardener.cloud
    prometheus-shoot-shoot--local--local-0.ingress.local.seed.local.gardener.cloud
    plutono-shoot--local--local.ingress.local.seed.local.gardener.cloud
    vlsingle-victoria-logs-garden.ingress.local.seed.local.gardener.cloud
    vlsingle-victoria-logs-shoot--local--local.ingress.local.seed.local.gardener.cloud
)
for record in "${records[@]}"; do
    if grep -qF -- "$record" /etc/hosts; then
        pass "\"$record\" found in /etc/hosts"
    else
        fail "\"$record\" not found in /etc/hosts"
    fi
done

# --- Result ---
echo "---"
if [[ "$failed" -eq 1 ]]; then
    echo "Some checks failed."
    exit 1
else
    echo "All checks passed."
fi
