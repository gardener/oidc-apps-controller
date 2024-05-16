# Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

NAME                        := oidc-apps-controller
REGISTRY                    ?= europe-docker.pkg.dev/gardener-project/snapshots
IMAGE_PREFIX                ?= $(REGISTRY)/gardener/extensions
REPO_ROOT                   := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BIN                         := $(REPO_ROOT)/bin
VERSION                     := $(shell cat "$(REPO_ROOT)/VERSION")
EFFECTIVE_VERSION           := $(VERSION)-$(shell git rev-parse HEAD)
LD_FLAGS                    ?= $(shell $(REPO_ROOT)/hack/get-build-ld-flags.sh k8s.io/component-base $(REPO_ROOT)/VERSION $(BINARY))
PLATFORM                    := linux/amd64,linux/arm64
ENVTEST_K8S_VERSION         ?= 1.29.3


ifneq ($(strip $(shell git status --porcelain 2>/dev/null)),)
	EFFECTIVE_VERSION := $(EFFECTIVE_VERSION)-dirty
endif

#########################################
# Tools                                 #
#########################################

TOOLS_DIR                   := $(REPO_ROOT)/hack/tools
TOOLS_DIR_BIN               := $(TOOLS_DIR)/bin
include $(REPO_ROOT)/hack/tools.mk

KUBEBUILDER_ASSETS          := $(shell $(TOOLS_DIR_BIN)/setup-envtest use $(ENVTEST_K8S_VERSION) \
									--bin-dir=$(TOOLS_DIR_BIN) -i -p path 2>/dev/null || true)

.DEFAULT_GOAL := build
#################################################################
# Rules related to binary build, Docker image build and release #
#################################################################

.PHONY: docker-images
docker-images:
	@docker buildx build --push --platform=$(PLATFORM) --build-arg LD_FLAGS="$(LD_FLAGS)" \
	-t $(IMAGE_PREFIX)/$(NAME):$(VERSION) -t $(IMAGE_PREFIX)/$(NAME):latest \
	-f Dockerfile .

#####################################################################
# Rules for verification, formatting, linting, testing and cleaning #
#####################################################################

.PHONY: build
build: format check
	@mkdir -p $(BIN)
	@go mod tidy
	@EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) GOBIN=$(BIN) \
		CGO_ENABLED=0 go build -ldflags="$(LD_FLAGS)" \
	  	-o $(BIN)/$(NAME) $(REPO_ROOT)/cmd/main.go

.PHONY: clean
clean: test-clean
	@$(shell find $(REPO_ROOT)/example -type f -name "controller-registration.yaml" -exec rm '{}' \;)
	@go clean -r $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...
	@GOBIN=$(BIN) go clean -i $(REPO_ROOT)/cmd/main.go

.PHONY: check
check: $(GOLANGCI_LINT)
	@$(REPO_ROOT)/hack/check.sh --golangci-lint-config=$(REPO_ROOT)/.golangci.yaml $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...

.PHONY: generate
generate:
	@go generate $(REPO_ROOT)/charts/... $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...

.PHONY: format
format: $(GOIMPORTS) $(GOIMPORTSREVISER)
	@gofmt -l -w $(REPO_ROOT)/cmd $(REPO_ROOT)/pkg
	@GOIMPORTS_REVISER_OPTIONS="-imports-order std,project,general,company" \
		$(REPO_ROOT)/hack/format.sh ./cmd ./pkg

.PHONY: test
test: $(MOCKGEN)
	@go generate $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...
	@go test $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...

.PHONY: envtest
envtest: $(SETUP_ENVTEST)
	@go test $(REPO_ROOT)/test/... -v -timeout 10m

.PHONY: test-clean
test-clean:

.PHONY: verify
verify: format check test envtest

.PHONY: add-license-headers
add-license-headers: $(GO_ADD_LICENSE)
	@$(REPO_ROOT)/hack/add-license-header.sh
