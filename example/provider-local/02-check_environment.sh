#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
# SPDX-License-Identifier: Apache-2.0


set -e
dir="$(dirname "$0")"

OPENSSL=
LDAPSEARCH=

function check_commands {
    commands="cfssl cfssljson jq docker kubectl curl"
    for cmd in $commands; do
        if ! command -v $cmd &> /dev/null; then
            printf '\u274c %s not found\n' $cmd
            exit
        fi
    done
    printf '\u2714 all required commands found\n'


    optional="openssl ldapsearch slappasswd"
    for cmd in $optional; do
        if ! command -v $cmd &> /dev/null; then
            printf '%s not found, but it is optional\n' $cmd
        else
            printf '\u2714 optional command "%s" found\n' $cmd
            if [[ $cmd == "openssl" ]]; then
                OPENSSL=$(command -v openssl)
            fi
            if [[ $cmd == "ldapsearch" ]]; then
                LDAPSEARCH=$(command -v ldapsearch)
            fi
        fi
    done
}

function check_ldap_is_configured {

    if [[ ! -f $dir/configs/local.ldif ]]; then
        printf '\u274c "local.ldif" not found. Please rename the provided local.ldif.tmp template and set the userpassword: fields for operator and project-viewer\n' && exit
    fi

    if grep -q 'userpassword: # TODO: Add' $dir/configs/local.ldif; then
        printf '\u274c Found an entry in local.ldif with userpassword not set:\n' && exit
    fi
    printf '\u2714 "local.ldif" has userpassword set\n'
}

function check_provider_local {

    networks=$(docker network ls --format "{{.Name}}" | tr '\n' ' ')
    if grep -q "kind" <<< $networks; then
        printf '\u2714 "kind" network found\n'
    else
        printf '\u274c "kind" network not found... TODO\n'
        exit
    fi

    ipam=$(docker network inspect kind -f "{{range .IPAM.Config}}{{.Subnet}} {{end}}")
    if grep -q "172.18.0.0/16" <<< $ipam ; then
        printf '\u2714 "172.18.0.0/16 subnet found\n'
    else
        printf '\u274c "172.18.0.0/16 subnet not found... TODO\n' && exit
    fi

    garden=$(docker network inspect kind -f "{{range .Containers}}{{.Name}} {{end}}")
    if grep -q "gardener-local-control-plane" <<< $garden ; then
        printf '\u2714 "gardener-local-control-plane" found\n'
    else
        printf '\u274c "gardener-local-control-plane" container not found\n'&& exit
    fi

    version=$(docker compose version)
    if grep -q "version v2" <<< $version ; then
        printf "\u2714 docker compose v2 found\n"
    else
        printf "\u274c docker compose: $version. Expected v2... and higher\n" && exit
    fi
}

function check_dex_is_up_and_running {

    if grep -q "127.0.0.1 dexidp" <<< $(cat /etc/hosts); then
        printf '\u2714 "127.0.0.1 dexidp" is present in /etc/hosts\n'
    else
        printf '\u274c "127.0.0.1 dexidp" not found in /etc/hosts' && exit
    fi

    if grep -q "dexidp" <<< $(docker ps --format json | jq -cr ".Names"); then
        printf '\u2714 "dex" is up and running\n'
    else
        printf '\u274c "dex" is not running\n' && exit
    fi

    response_code=$(curl --cacert $dir/certs/ca.pem -s -o /dev/null -I \
            --max-time 60 --retry 5 --retry-delay 1 --retry-max-time 10 \
            -w "%{http_code}" "https://dexidp:5556/.well-known/openid-configuration" )
    if [[ $response_code -eq 200 ]]; then
        printf '\u2714 ".well-known/openid-configuration" endpoint is up\n'
    else
        printf '\u274c ".well-known/openid-configuration" endpoint is down\n' && exit
    fi

}

function check_ldap_is_up_and_running {

    if grep -q "ldap" <<< $(docker ps --format json | jq -cr ".Names"); then
        printf '\u2714 "ldap" is up and running\n'
    else
        printf '\u274c "ldap" is not running\n' && exit
    fi

   if [[ -n $LDAPSEARCH ]]; then
        echo
        printf "ldap records \u2192\n"
        echo
       ldapsearch -LLL -H ldap://localhost:389 -x -D "cn=readonly,dc=local" -w "readonly"  -b "ou=Groups,dc=local" "objectClass=groupOfNames"
    fi

}

function check_seed_annotation {
    annotation="oidc-apps.extensions.gardener.cloud/client-name"
    present=$(kubectl get seed -n garden -o jsonpath='{.items[].metadata.annotations}')

    if grep -q $annotation <<< $present; then
        printf "\u2714 $annotation annotation found\n"
    else
        printf '\u274c "oidc-apps.extensions.gardener.cloud/client-name" annotation not found\n' && exit
    fi
}


function check_garden_clusterroles {
    clusterrols=$(kubectl get clusterrole -n garden -o jsonpath='{.items[*].metadata.name}')
    if grep -q "oidc-apps-subjectaccessreviews" <<< $clusterrols; then
        printf '\u2714 "oidc-apps-subjectaccessreviews" clusterrole found\n'
    else
        printf '\u274c "oidc-apps-subjectaccessreviews" clusterrole not found\n' && exit
    fi

    if grep -q "gardener.cloud:system:observabilityapps-operators" <<< $clusterrols; then
        printf '\u2714 "gardener.cloud:system:observabilityapps-operators" clusterrole found\n'
    else
        printf '\u274c "gardener.cloud:system:observabilityapps-operators" clusterrole not found\n' && exit
    fi

    if grep -q "gardener.cloud:system:observabilityapps-projects" <<< $clusterrols; then
        printf '\u2714 "gardener.cloud:system:observabilityapps-projects" clusterrole found\n'
    else
        printf '\u274c "gardener.cloud:system:observabilityapps-projects" clusterrole not found\n' && exit
    fi

}

function check_garden_clusterrolesbindings {
    clusterrolsbindings=$(kubectl get clusterrolebinding -n garden -o jsonpath='{.items[*].metadata.name}')
    if grep -q "gardener.cloud:system:observabilityapps-operators" <<< $clusterrolsbindings; then
        printf '\u2714 "gardener.cloud:system:observabilityapps-operators" clusterrolebinding found\n'
    else
        printf '\u274c "gardener.cloud:system:observabilityapps-operators" clusterrolebinding not found\n' && exit
    fi

}

function check_kubeconfig {
    current_context=$(cat $KUBECONFIG | yq '.current-context')
    if grep -q "kind-gardener-local" <<< $current_context; then
        printf '\u2714 KUBECONFIG is set to kind-gardener-local context\n'
    else
        printf '\u274c KUBECONFIG is not set to kind-gardener-local context\n' && exit
    fi
}

function check_hosts {

    # oidc-apps-controller provider local setup
    records=(
        dexidp
        plutono-garden.ingress.local.seed.local.gardener.cloud
        prometheus-seed-garden-0.ingress.local.seed.local.gardener.cloud
        prometheus-aggregate-garden-0.ingress.local.seed.local.gardener.cloud
        prometheus-cache-garden-0.ingress.local.seed.local.gardener.cloud
        prometheus-shoot-shoot--local--local-0.ingress.local.seed.local.gardener.cloud
        plutono-shoot--local--local.ingress.local.seed.local.gardener.cloud
    )
    for record in "${records[@]}"; do
        if grep -qF -- "$record" /etc/hosts; then
            printf '\u2714 "%s" is present in /etc/hosts\n' $record
        else
            printf '\u274c "%s" not found in /etc/hosts\n' $record && exit
        fi
    done

}


check_commands
check_ldap_is_configured
check_provider_local
check_dex_is_up_and_running
check_ldap_is_up_and_running
check_kubeconfig
check_seed_annotation
check_garden_clusterroles
check_garden_clusterrolesbindings
check_hosts
