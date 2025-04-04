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
EFFECTIVE_VERSION           := $(VERSION)-$(shell git rev-parse --short HEAD)
SRC_DIRS                    := $(shell go list -f '{{.Dir}}' $(REPO_ROOT)/...)
LD_FLAGS                    := -w -s $(shell $(REPO_ROOT)/hack/get-build-ld-flags.sh)
BUILD_PLATFORM              ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')
BUILD_ARCH                  ?= $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

TOOLS_DIR                   := $(REPO_ROOT)/tools
ENVTEST_K8S_VERSION         ?= 1.32.0

GCI_OPT                     ?= -s standard -s default -s "prefix($(shell go list -m))" --skip-generated

ifneq ($(strip $(shell git status --porcelain 2>/dev/null)),)
	EFFECTIVE_VERSION := $(EFFECTIVE_VERSION)-dirty
endif
IMAGE_TAG                   := $(EFFECTIVE_VERSION)

$(TOOLS_DIR):
	@mkdir -p $(TOOLS_DIR)

#########################################
# Targets                                 #
#########################################
.DEFAULT_GOAL := all
all: check test envtest build

.PHONY: verify
verify: check test envtest sast

.PHONY: verify-extended
verify-extended: check test envtest sast-report

#################################################################
# Rules related to binary build, Docker image build and release #
#################################################################
.PHONY: docker-images
docker-images:
	@docker build \
		--tag $(IMAGE_REPOSITORY):latest \
		--tag $(IMAGE_REPOSITORY):$(IMAGE_TAG) \
		-f Dockerfile --target oidc-apps-controller $(REPO_ROOT)

.PHONY: docker-push
docker-push:
	@docker push $(IMAGE_REPOSITORY):latest
	@docker push $(IMAGE_REPOSITORY):$(IMAGE_TAG)


#####################################################################
# Rules for verification, formatting, linting, testing and cleaning #
#####################################################################
.PHONY: tidy
tidy:
	@go mod tidy

.PHONY: build
build: tidy check
	@CGO_ENABLED=0 go build -ldflags="$(LD_FLAGS)" \
	  	-o $(REPO_ROOT)/build/$(NAME) $(REPO_ROOT)/cmd/main.go

.PHONY: gci
gci: tidy
	@echo "Running gci..."
	@go tool gci write $(GCI_OPT) $(SRC_DIRS)

.PHONY: clean
clean:
	@echo "Running $@..."
	@rm -f $(REPO_ROOT)/build/$(NAME)
	@rm -f $(REPO_ROOT)/gosec-report.sarif
	@go tool setup-envtest cleanup --bin-dir=$(TOOLS_DIR)

.PHONY: fmt
fmt: tidy
	@echo "Running $@..."
	@go tool golangci-lint fmt \
    	--config=$(REPO_ROOT)/.golangci.yaml \
    	$(SRC_DIRS)

.PHONY: check
check: tidy fmt gci lint

.PHONY: lint
lint: tidy
	@echo "Running $@..."
	@go tool golangci-lint run \
	 	--config=$(REPO_ROOT)/.golangci.yaml \
		$(SRC_DIRS)

.PHONY: test
test: tidy
	@go generate $(SRC_DIRS)
	@go tool gotestsum --format-hide-empty-pkg $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...

.PHONY: envtest
envtest: tidy
	@KUBEBUILDER_ASSETS=$(shell \
		go tool setup-envtest \
		use $(ENVTEST_K8S_VERSION) \
		--bin-dir=$(TOOLS_DIR) \
		-p path 2>/dev/null || true) \
		go tool gotestsum \
			--format-hide-empty-pkg \
			$(REPO_ROOT)/test/... \
			--ginkgo.v \
			-timeout 10m

.PHONY: add-license-headers
add-license-headers: tidy
	@$(REPO_ROOT)/hack/add-license-header.sh

.PHONY: govulncheck
govulncheck: tidy
	@go tool govulncheck $(REPO_ROOT)/...

.PHONY: sast
sast: tidy $(GOSEC)
	@$(REPO_ROOT)/hack/sast.sh

.PHONY: sast-report
sast-report: tidy $(GOSEC)
	@$(REPO_ROOT)/hack/sast.sh --gosec-report true
