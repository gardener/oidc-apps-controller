# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

options="--connect-timeout 2 --max-time 10 --retry 3 --retry-delay 1"
options="$options --cacert /etc/kube-rbac-proxy/ca.crt"
options="$options -sSv"
check="curl ${options} "${OIDC_URL}/.well-known/openid-configuration""
while true; do
  $check || true
  sleep 120
done