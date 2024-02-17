# This document describes how to setup the scenario using provider-local dev environment

The dev environment consists of provider-local setup and DexIdp with OpenLdap as a backend to facilitate the OIDC authentication. The DexIdp and OpenLdap containers are provisioned with docker-compose in the same Kind network created by the provider-local scenario.

Required dependencies: docker-compose, cfssl

Prerequisites:

- A fully function gardener provider-local setup with KUBECONFIG env variable set accordingly.
- Following records are present in /etc/hosts. Here is how to append them.

```sh
cat <<EOF | sudo tee -a /etc/hosts
# oidc-apps-controller provider local setup
127.0.0.1 dexidp
# setup seed
127.0.0.1 plutono-garden.ingress.local.seed.local.gardener.cloud
127.0.0.1 seed-prometheus-garden-0.ingress.local.seed.local.gardener.cloud
127.0.0.1 aggregate-prometheus-garden-0.ingress.local.seed.local.gardener.cloud
127.0.0.1 prometheus-cache-garden-0.ingress.local.seed.local.gardener.cloud
# setup shoot
127.0.0.1 pr-404698-0.ingress.local.seed.local.gardener.cloud
127.0.0.1 pl-b5e187.ingress.local.seed.local.gardener.cloud
EOF
```

Setup:

1. Steps 00-01:
   Follow 00- and 01- groups of shell scripts to bring up DexIdP and OpenLdap components
2. Step 02:
   Verify the environment with 02-check_environment.sh
3. Step 03
   Apply the odic-apps-controller setup with 03-setup-

Following URLs shall trigger OIDC authorization flow:

- [https://plutono-garden.ingress.local.seed.local.gardener.cloud/oauth2/callback](https://plutono-garden.ingress.local.seed.local.gardener.cloud/oauth2/callback)
- [https://seed-prometheus-garden-0.ingress.local.seed.local.gardener.cloud/oauth2/callback](https://seed-prometheus-garden-0.ingress.local.seed.local.gardener.cloud/oauth2/callback)
- [https://aggregate-prometheus-garden-0.ingress.local.seed.local.gardener.cloud/oauth2/callback](https://aggregate-prometheus-garden-0.ingress.local.seed.local.gardener.cloud/oauth2/callback)

In case the local shoot is provided:

1. Step 01
   Patch the project resource, adding additional member with 04-setup_project.sh

Following URLs shall trigger OIDC authorization flow:

- [https://pr-404698-0.ingress.local.seed.local.gardener.cloud/oauth2/callback](https://pr-404698-0.ingress.local.seed.local.gardener.cloud/oauth2/callback)
