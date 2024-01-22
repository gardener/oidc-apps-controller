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

ifneq ($(strip $(shell git status --porcelain 2>/dev/null)),)
	EFFECTIVE_VERSION := $(EFFECTIVE_VERSION)-dirty
endif

#########################################
# Tools                                 #
#########################################

TOOLS_DIR := $(REPO_ROOT)/hack/tools
include $(REPO_ROOT)/hack/tools.mk

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
build:
	@mkdir -p $(BIN)
	@EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) GOBIN=$(BIN) \
		CGO_ENABLED=0 go build -ldflags="$(LD_FLAGS)" \
	  	-o $(BIN)/$(NAME) $(REPO_ROOT)/cmd/main.go

.PHONY: clean
clean: test-clean
	@go clean --testcache
	@go clean -r $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...
	@GOBIN=$(BIN) go clean -i $(REPO_ROOT)/cmd/main.go

.PHONY: check
check: $(GOLANGCI_LINT)
	@$(REPO_ROOT)/hack/check.sh --golangci-lint-config=$(REPO_ROOT)/.golangci.yaml $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...

.PHONY: generate
generate:
	@go generate $(REPO_ROOT)/...

.PHONY: format
format:
	@gofmt -l -w $(REPO_ROOT)/cmd $(REPO_ROOT)/pkg

.PHONY: test
test:
	@go test $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...

.PHONY: test-clean
test-clean:
	@rm -f $(REPO_ROOT)/test.*

.PHONY: verify
verify: check format test

.PHONY: add-license-headers
add-license-headers: $(GO_ADD_LICENSE)
	@$(REPO_ROOT)/hack/add-license-header.sh