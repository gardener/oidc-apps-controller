#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


set -e
dir="$(dirname "$0")"

pushd ${dir} > /dev/null 2>&1
trap "popd > /dev/null 2>&1" EXIT


# Clean up ldap volume
docker compose down
docker volume rm provider-local_ldap -f
docker volume rm provider-local_sqlite3 -f

docker compose up -d

while [[ $(docker inspect --format=json dexidp | jq '.[0].State.Running') == "false" ]]; do
    echo "waiting for dexidp to start"
    sleep 1
done
printf '\u2714 dexidp is running\n'

while [[ $(docker inspect --format=json ldap | jq '.[0].State.Running') == "false" ]]; do
    echo "waiting for ldap to start"
    sleep 1
done
printf '\u2714 ldap is running\n'
