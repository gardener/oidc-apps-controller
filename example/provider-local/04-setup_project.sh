#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
# SPDX-License-Identifier: Apache-2.0


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
