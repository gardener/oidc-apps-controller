# Provider-local dev environment

The dev environment consists of a provider-local Gardener setup with DexIdP and OpenLDAP as a backend to facilitate OIDC authentication. The DexIdP and OpenLDAP containers are provisioned with docker-compose in the same Kind network created by the provider-local scenario.

## Required dependencies

- docker-compose
- cfssl (for certificate generation)
- kustomize (v5+, standalone binary)
- kind
- yq

## Prerequisites

- A fully functional gardener provider-local setup with KUBECONFIG env variable set to `kind-gardener-local` context.
- A shoot named `local` in the `garden-local` namespace.
- Following records are present in /etc/hosts:

```sh
cat <<EOF | sudo tee -a /etc/hosts
# oidc-apps-controller provider local setup
127.0.0.1 dexidp
# setup seed
127.0.0.1 plutono-garden.ingress.local.seed.local.gardener.cloud
127.0.0.1 prometheus-seed-garden-0.ingress.local.seed.local.gardener.cloud
127.0.0.1 prometheus-aggregate-garden-0.ingress.local.seed.local.gardener.cloud
127.0.0.1 prometheus-cache-garden-0.ingress.local.seed.local.gardener.cloud
127.0.0.1 vlsingle-victoria-logs-garden.ingress.local.seed.local.gardener.cloud
# setup shoot
127.0.0.1 prometheus-shoot-shoot--local--local-0.ingress.local.seed.local.gardener.cloud
127.0.0.1 plutono-shoot--local--local.ingress.local.seed.local.gardener.cloud
127.0.0.1 vlsingle-victoria-logs-shoot--local--local.ingress.local.seed.local.gardener.cloud
EOF
```

## Deploy

From the repository root, run:

```sh
make deploy
```

This single command will:
1. Validate prerequisites (kubectl context is `kind-gardener-local`, shoot `local` exists)
2. Generate TLS certificates if missing (CA, Dex, wildcard)
3. Generate LDAP config (`local.ldif`) with default passwords if missing
4. Start DexIdP and OpenLDAP containers if not already running
5. Build the controller Docker image for the kind node's architecture
6. Load the image into the kind cluster
7. Apply RBAC resources, project member patch, ControllerDeployment, and ControllerRegistration via kustomize

## Verify environment

To check that all prerequisites, services, Gardener resources, and /etc/hosts entries are correctly configured:

```sh
make deploy-check
```

## OIDC authorization flow URLs

Seed:
- https://plutono-garden.ingress.local.seed.local.gardener.cloud/oauth2/callback
- https://prometheus-seed-garden-0.ingress.local.seed.local.gardener.cloud/oauth2/callback
- https://prometheus-aggregate-garden-0.ingress.local.seed.local.gardener.cloud/oauth2/callback
- https://prometheus-cache-garden-0.ingress.local.seed.local.gardener.cloud/oauth2/callback
- https://vlsingle-victoria-logs-garden.ingress.local.seed.local.gardener.cloud/oauth2/callback

Shoot:
- https://prometheus-shoot-shoot--local--local-0.ingress.local.seed.local.gardener.cloud/oauth2/callback
- https://plutono-shoot--local--local.ingress.local.seed.local.gardener.cloud/oauth2/callback
- https://vlsingle-victoria-logs-shoot--local--local.ingress.local.seed.local.gardener.cloud/oauth2/callback
