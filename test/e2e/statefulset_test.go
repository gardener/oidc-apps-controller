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

package e2e

import (
	"context"
	_ "embed"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("Oidc Apps StatefulSets Framework Test", func() {

	var (
		_      context.Context
		cancel context.CancelFunc
	)

	// Initialize the test environment
	BeforeEach(func() {
		_, cancel = context.WithTimeout(
			logr.NewContext(context.Background(), _log),
			30*time.Second,
		)

	})

	AfterEach(func() {
		cancel()
	})
	Context("when a statefulset is a target", func() {
		It("there shall be  auth & autz proxies present in the statefulset", func() {})

		When("the statefulset is created with two pods", func() {
			It("there shall be an ingress and service for each pod", func() {})
		})
		It("there shall be oauth2 and kube-rbac secrets present in the statefulset namespace", func() {})
		When("the statefulset is scaled to 0", func() {
			It("there shall be no ingress & services for pods present in the statefulset", func() {})
		})
		When("the statefulset is deleted", func() {
			It("there shall be no auth & autz proxies present in the statefulset", func() {})
		})
	})
	Context("when a statefulset is not a target", func() {
		It("there shall be no auth & autz proxies present in the statefulset", func() {})
	})

})
