// Copyright 2024 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package test

import (
	_ "embed"

	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("Oidc Apps MutatingAdmission Framework Test", func() {
	Context("when a pod belongs to a target", func() {
		It("there shall be a auth & authz proxies in the pod templates spec", func() {})
		When("the pod is created with a service account with token", func() {
			It("there shall be a volume mount in the pod template spec", func() {})
		})
		When("there is a kubeconfig secret", func() {
			It("there shall be a kubeconfig volume in the pod templates spec", func() {})
		})
	})
	Context("when a pod does not belong to a target", func() {
		It("there shall be no ", func() {})
	})
})
