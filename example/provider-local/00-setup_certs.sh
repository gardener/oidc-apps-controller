#!/usr/bin/env bash

set -e
dir="$(dirname "$0")"

function create_certs {
    mkdir -p ${dir}/certs
    pushd ${dir}/certs > /dev/null 2>&1
    trap "popd > /dev/null 2>&1" EXIT

    ([[ ! -f "ca.pem" ]] || [[ ! -f "ca-key.pem" ]]) && \
        cfssl gencert -initca ../configs/ca.json | cfssljson -bare ca > /dev/null 2>&1

    if [[ -n $OPENSSL ]]; then
        echo "generated certificate: $(openssl x509 -in ca.pem -subject -noout)"
    fi

    ([[ ! -f "dex.pem" ]] || [[ ! -f "dex-key.pem" ]]) && \
        cfssl gencert -ca ca.pem -ca-key ca-key.pem ../configs/dex.json | cfssljson -bare dex > /dev/null 2>&1
    if [[ -n $OPENSSL ]]; then
        echo "generated certificate: $(openssl x509 -in dex.pem -subject -noout)"
    fi

}

create_certs