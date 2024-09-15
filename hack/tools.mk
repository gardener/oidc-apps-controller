# Copyright 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

# This make file is supposed to be included in the top-level make file.
# It can be reused by repos vendoring g/g to have some common make recipes for building and installing development
# tools as needed.
# Recipes in the top-level make file should declare dependencies on the respective tool recipes (e.g. $(CONTROLLER_GEN))
# as needed. If the required tool (version) is not built/installed yet, make will make sure to build/install it.
# The *_VERSION variables in this file contain the "default" values, but can be overwritten in the top level make file.

ifeq ($(strip $(shell go list -m 2>/dev/null)),oidc-apps-controller)
TOOLS_PKG_PATH             := ./hack/tools
endif

TOOLS_BIN_DIR              := $(TOOLS_DIR)/bin
GOLANGCI_LINT              := $(TOOLS_BIN_DIR)/golangci-lint
GOIMPORTS                  := $(TOOLS_BIN_DIR)/goimports
GOIMPORTSREVISER           := $(TOOLS_BIN_DIR)/goimports-reviser
GO_ADD_LICENSE             := $(TOOLS_BIN_DIR)/addlicense
MOCKGEN                    := $(TOOLS_BIN_DIR)/mockgen
SETUP_ENVTEST		       := $(TOOLS_BIN_DIR)/setup-envtest
GOVULNCHECK                := $(TOOLS_BIN_DIR)/govulncheck

# default tool versions
GOLANGCI_LINT_VERSION ?= v1.61.0
GO_ADD_LICENSE_VERSION ?= v1.1.1
GOIMPORTSREVISER_VERSION ?= v3.6.4
GOVULNCHECK_VERSION ?= v1.1.3
GOIMPORTS_VERSION ?= $(call version_gomod,golang.org/x/tools)
MOCKGEN_VERSION ?= $(call version_gomod,github.com/golang/mock)
SETUP_ENVTEST_VERSION ?= $(call version_gomod,sigs.k8s.io/controller-runtime/tools/setup-envtest)

export TOOLS_BIN_DIR := $(TOOLS_BIN_DIR)
export PATH := $(abspath $(TOOLS_BIN_DIR)):$(PATH)


#########################################
# Common                                #
#########################################

# Tool targets should declare go.mod as a prerequisite, if the tool's version is managed via go modules. This causes
# make to rebuild the tool in the desired version, when go.mod is changed.
# For tools where the version is not managed via go.mod, we use a file per tool and version as an indicator for make
# whether we need to install the tool or a different version of the tool (make doesn't rerun the rule if the rule is
# changed).

# Use this "function" to add the version file as a prerequisite for the tool target: e.g.
#   $(HELM): $(call tool_version_file,$(HELM),$(HELM_VERSION))
tool_version_file = $(TOOLS_BIN_DIR)/.version_$(subst $(TOOLS_BIN_DIR)/,,$(1))_$(2)

# Use this function to get the version of a go module from go.mod
version_gomod = $(shell go list -mod=mod -f '{{ .Version }}' -m $(1))

# This target cleans up any previous version files for the given tool and creates the given version file.
# This way, we can generically determine, which version was installed without calling each and every binary explicitly.
$(TOOLS_BIN_DIR)/.version_%:
	@mkdir -p  $(TOOLS_BIN_DIR)
	@version_file=$@; rm -f $${version_file%_*}*
	@touch $@

.PHONY: clean-tools-bin
clean-tools-bin:
	rm -rf $(TOOLS_BIN_DIR)/*

.PHONY: import-tools-bin
import-tools-bin:
ifeq ($(shell if [ -d $(TOOLS_BIN_SOURCE_DIR) ]; then echo "found"; fi),found)
	@echo "Copying tool binaries from $(TOOLS_BIN_SOURCE_DIR)"
	@cp -rpT $(TOOLS_BIN_SOURCE_DIR) $(TOOLS_BIN_DIR)
endif

.PHONY: create-tools-bin
create-tools-bin: $(GOLANGCI_LINT) $(GO_ADD_LICENSE) $(GOIMPORTS) $(MOCKGEN) $(GOIMPORTSREVISER) $(SETUP_ENVTEST)

#########################################
# Tools                                 #
#########################################

$(GOLANGCI_LINT): $(call tool_version_file,$(GOLANGCI_LINT),$(GOLANGCI_LINT_VERSION))
	@# CGO_ENABLED has to be set to 1 in order for golangci-lint to be able to load plugins
	@# see https://github.com/golangci/golangci-lint/issues/1276
	GOBIN=$(abspath $(TOOLS_BIN_DIR)) CGO_ENABLED=1 go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(GOVULNCHECK): $(call tool_version_file,$(GOVULNCHECK),$(GOVULNCHECK_VERSION))
	GOBIN=$(abspath $(TOOLS_BIN_DIR)) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

$(GOIMPORTS): $(call tool_version_file,$(GOIMPORTS),$(GOIMPORTS_VERSION))
	GOBIN=$(abspath $(TOOLS_BIN_DIR)) go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)

$(GOIMPORTSREVISER): $(call tool_version_file,$(GOIMPORTSREVISER),$(GOIMPORTSREVISER_VERSION))
	GOBIN=$(abspath $(TOOLS_BIN_DIR)) go install github.com/incu6us/goimports-reviser/v3@$(GOIMPORTSREVISER_VERSION)

$(GO_ADD_LICENSE):  $(call tool_version_file,$(GO_ADD_LICENSE),$(GO_ADD_LICENSE_VERSION))
	GOBIN=$(abspath $(TOOLS_BIN_DIR)) go install github.com/google/addlicense@$(GO_ADD_LICENSE_VERSION)

$(MOCKGEN): $(call tool_version_file,$(MOCKGEN),$(MOCKGEN_VERSION))
	GOBIN=$(abspath $(TOOLS_BIN_DIR)) go install github.com/golang/mock/mockgen@$(MOCKGEN_VERSION)

$(SETUP_ENVTEST): $(call tool_version_file,$(SETUP_ENVTEST),$(SETUP_ENVTEST_VERSION))
	@GOBIN=$(abspath $(TOOLS_BIN_DIR)) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VERSION)
	@$(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(TOOLS_BIN_DIR)
