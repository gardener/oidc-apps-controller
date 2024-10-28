#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


set -e
dir="$(dirname "$0")"

function __cleanup {
  local res=$1
  echo "cleanup ${res}"
  rm -rf ${res}
}

WORK_DIR="$( mktemp -d -t tmp-XXXXXX )"
trap "__cleanup $WORK_DIR" EXIT

echo "Setting userpassword for operator and project-viewer in local.ldif"

echo "Enter password for the operator:"
read -s operator_password
if command -v slappasswd &> /dev/null; then
    hash=$(slappasswd -s $operator_password)
    sed "s|^userpassword: # TODO: Add operator password.*|userpassword: $hash|" $dir/configs/local.ldif.tmpl > $WORK_DIR/local.ldif
else
    echo "slappasswd not found, passwors is in plain text"
    sed "s|^userpassword: # TODO: Add operator password.*|userpassword: $operator_password|" $dir/configs/local.ldif.tmpl > $WORK_DIR/local.ldif
    exit
fi

echo "Enter password for the project-viewer:"
read -s project_viewer_password
if command -v slappasswd &> /dev/null; then
    hash=$(slappasswd -s $project_viewer_password)
    sed -i "s|^userpassword: # TODO: Add project-viewer password.*|userpassword: $hash|" $WORK_DIR/local.ldif
else
    echo "slappasswd not found, password is in plain text"
    sed -i "s|^userpassword: # TODO: Add project-viewer password.*|userpassword: $project_viewer_password|" $WORK_DIR/local.ldif
    exit
fi

cp $WORK_DIR/local.ldif $dir/configs/local.ldif
echo "local.ldif updated with userpassword for operator and project-viewer"
