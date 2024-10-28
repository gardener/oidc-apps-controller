#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


set -e
dir=$(dirname $0)

echo "> Adding Apache License header to all go files where it is not present"

temp_file=$(mktemp)
trap "rm -f $temp_file" EXIT
sed 's|^// *||' $dir/license_boilerplate.txt > $temp_file

$dir/../tools/addlicense \
  -f $temp_file \
  -y "$(date +"%Y")" \
  -l apache \
  -ignore ".idea/**" \
  -ignore ".vscode/**" \
  -ignore "dev/**" \
  -ignore "**/*.md" \
  -ignore "**/*.yaml" \
  -ignore "**/Dockerfile" \
  -ignore "pkg/component/**/*.sh" \
  .
