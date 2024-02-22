# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

options="--connect-timeout 10 --max-time 10 --retry 3 --retry-delay 2"
options="$options --retry-max-time 30 --cacert /etc/kube-rbac-proxy/ca.crt"
options="$options -w \"%{http_code}\" -sS -o /dev/null"
check="curl ${options} "${OIDC_URL}/.well-known/openid-configuration""
until  $( $check |grep -q "200" ); do
  echo "Executing ${check} returns non-200 response, retrying..."
  sleep 1
done