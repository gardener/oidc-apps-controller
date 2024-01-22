# Copyright 2024 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

options="--connect-timeout 10 --max-time 10 --retry 3 --retry-delay 2"
options="$options --retry-max-time 30 --cacert /etc/kube-rbac-proxy/ca.crt"
options="$options -w \"%{http_code}\" -sS -o /dev/null"
check="curl ${options} "${OIDC_URL}/.well-known/openid-configuration""
until  $( $check |grep -q "200" ); do
  echo "Executing ${check} returns non-200 response, retrying..."
  sleep 1
done