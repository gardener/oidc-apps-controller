#!/usr/bin/env bash

set -e
dir="$(dirname "$0")"


kubectl patch -n garden-local project local --type=merge -p '
{
   "spec":{
      "members":[
         {
            "apiGroup":"rbac.authorization.k8s.io",
            "kind":"User",
            "name":"project-viewer@gardener.local",
            "role":"viewer"
         }
      ]
   }
}'
