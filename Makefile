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
REGISTRY                    ?= europe-docker.pkg.dev/gardener-project/snapshots/gardener/extensions
IMAGE_REPOSITORY            := $(REGISTRY)/$(NAME)
REPO_ROOT                   := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
VERSION                     := $(shell cat "$(REPO_ROOT)/VERSION")
EFFECTIVE_VERSION           := $(VERSION)-$(shell git rev-parse HEAD)
SRC_DIRS                    := $(shell go list -f '{{.Dir}}' $(REPO_ROOT)/...)
LD_FLAGS                    := $(shell $(REPO_ROOT)/hack/get-build-ld-flags.sh)
BUILD_PLATFORM              ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')
BUILD_ARCH                  ?= $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
IMAGE_TAG                   := $(VERSION)

PKG_DIR                     := $(REPO_ROOT)/pkg
TOOLS_DIR                   := $(REPO_ROOT)/tools
ENVTEST_K8S_VERSION         ?= 1.30.0

ifneq ($(strip $(shell git status --porcelain 2>/dev/null)),)
	EFFECTIVE_VERSION := $(EFFECTIVE_VERSION)-dirty
endif

#########################################
# Tools                                 #
#########################################

include $(REPO_ROOT)/hack/tools.mk

.DEFAULT_GOAL := all
#####################################################################
# Rules for verification, formatting, linting, testing and cleaning #
#####################################################################

.PHONY: all
all: check test envtest build generate-controller-registration

.PHONY: build
build: format
	@go mod tidy
	@go mod download
	@EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) GOBIN=$(BIN) \
		CGO_ENABLED=0 go build -ldflags="$(LD_FLAGS)" \
	  	-o $(REPO_ROOT)/build/$(NAME) $(REPO_ROOT)/cmd/main.go

.PHONY: clean
clean:
	@rm -f $(BIN)/$(NAME)

.PHONY: check
check: format $(GO_LINT)
	 @$(GO_LINT) run --config=$(REPO_ROOT)/.golangci.yaml --timeout 10m $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/... $(REPO_ROOT)/test/...
	 @go vet $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/... $(REPO_ROOT)/test/...

.PHONY: format
format:
	@gofmt -l -w $(REPO_ROOT)/cmd $(REPO_ROOT)/pkg $(REPO_ROOT)/test

.PHONY: generate-controller-registration
generate-controller-registration:
	@go generate $(REPO_ROOT)/charts/...

.PHONY: test
test: $(MOCKGEN)
	@go generate $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...
	@go test $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...

.PHONY: envtest
envtest: $(SETUP_ENVTEST)
	@KUBEBUILDER_ASSETS=$(shell $(TOOLS_DIR)/setup-envtest use $(ENVTEST_K8S_VERSION) --bin-dir=$(TOOLS_DIR) -i -p path 2>/dev/null || true) go test $(REPO_ROOT)/test/... --ginkgo.v -timeout 10m

.PHONY: goimports
goimports: goimports_tool goimports-reviser_tool

.PHONY: goimports_tool
goimports_tool: $(GOIMPORTS)
	@for dir in $(SRC_DIRS); do \
		$(GOIMPORTS) -w $$dir/; \
	done

.PHONY: goimports-reviser_tool
goimports-reviser_tool: $(GOIMPORTS_REVISER)
	@for dir in $(SRC_DIRS); do \
		GOIMPORTS_REVISER_OPTIONS="-imports-order std,project,general,company" \
		$(GOIMPORTS_REVISER) -recursive $$dir/; \
	done

.PHONY: add-license-headers
add-license-headers: $(GO_ADD_LICENSE)
	@$(REPO_ROOT)/hack/add-license-header.sh

.PHONY: govulncheck
govulncheck: $(GOVULNCHECK)
	@$(GOVULNCHECK) $(REPO_ROOT)/...

#################################################################
# Rules related to Docker image build and release #
#################################################################
.PHONY: docker-images
docker-images:
	@BUILD_ARCH=$(BUILD_ARCH) \
		$(REPO_ROOT)/hack/docker-image-build.sh "oidc-apps-controller" \
		$(IMAGE_REPOSITORY) $(IMAGE_TAG)

.PHONY: docker-push
docker-push:
	@$(REPO_ROOT)/hack/docker-image-push.sh "oidc-apps-controller" \
	$(IMAGE_REPOSITORY) $(IMAGE_TAG)
