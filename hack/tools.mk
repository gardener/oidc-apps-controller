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

# test dependencies
GINKGO                                     := $(TOOLS_DIR)/ginkgo
GINKGO_VERSION                             ?= $(call version_gomod,github.com/onsi/ginkgo/v2)

# goimports dependencies
GOIMPORTS                                  := $(TOOLS_DIR)/goimports
GOIMPORTS_VERSION                          ?= $(call version_gomod,golang.org/x/tools)

# goimports_reviser dependencies
GOIMPORTS_REVISER                          := $(TOOLS_DIR)/goimports-reviser
GOIMPORTS_REVISER_VERSION                  ?= v3.6.5

MOCKGEN                                    := $(TOOLS_DIR)/mockgen
MOCKGEN_VERSION                            ?= $(call version_gomod,go.uber.org/mock)

GO_ADD_LICENSE                             := $(TOOLS_DIR)/addlicense
GO_ADD_LICENSE_VERSION                     ?= $(call version_gomod,github.com/google/addlicense)

SETUP_ENVTEST		                       := $(TOOLS_DIR)/setup-envtest
SETUP_ENVTEST_VERSION                      ?= $(call version_gomod,sigs.k8s.io/controller-runtime/tools/setup-envtest)

GOVULNCHECK                                := $(TOOLS_DIR)/govulncheck
GOVULNCHECK_VERSION                        ?= $(call version_gomod,golang.org/x/vuln)

GO_ADD_LICENSE                             := $(TOOLS_DIR)/addlicense
GO_ADD_LICENSE_VERSION                     ?= $(call version_gomod,github.com/google/addlicense)

# gosec
GOSEC     	                               := $(TOOLS_DIR)/gosec
GOSEC_VERSION		                       ?= v2.21.4

GOTESTSUM                                  := $(TOOLS_DIR)/gotestsum
GOTESTSUM_VERSION                          ?= $(call version_gomod,gotest.tools/gotestsum)

TOOLS                                      := \
												$(GO_ADD_LICENSE) \
												$(GOIMPORTS) \
												$(GOIMPORTS_REVISER) \
												$(GOVULNCHECK) \
												$(MOCKGEN) \
												$(SETUP_ENVTEST) \
												$(GOSEC) \
												$(GOTESTSUM)

export PATH := $(abspath $(TOOLS_DIR)):$(PATH)


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
tool_version_file = $(TOOLS_DIR)/.version_$(subst $(TOOLS_DIR)/,,$(1))_$(2)

# Use this function to get the version of a go module from go.mod
version_gomod = $(shell go list -mod=mod -f '{{ .Version }}' -m $(1))

# This target cleans up any previous version files for the given tool and creates the given version file.
# This way, we can generically determine, which version was installed without calling each and every binary explicitly.
$(TOOLS_DIR)/.version_%:
	@mkdir -p  $(TOOLS_DIR)
	@version_file=$@; rm -f $${version_file%_*}*
	@touch $@

clean-tools:
	@rm -f $(TOOLS)

create-tools: tidy $(TOOLS)

#########################################
# Tools                                 #
#########################################

$(GOVULNCHECK): $(call tool_version_file,$(GOVULNCHECK),$(GOVULNCHECK_VERSION))
	@echo "install target: $@"
	@GOBIN=$(abspath $(TOOLS_DIR)) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

$(GOIMPORTS): $(call tool_version_file,$(GOIMPORTS),$(GOIMPORTS_VERSION))
	@echo "install target: $@"
	@GOBIN=$(abspath $(TOOLS_DIR)) go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)

$(GOIMPORTS_REVISER): $(call tool_version_file,$(GOIMPORTS_REVISER),$(GOIMPORTS_REVISER_VERSION))
	@echo "install target: $@"
	@GOBIN=$(abspath $(TOOLS_DIR)) go install github.com/incu6us/goimports-reviser/v3@$(GOIMPORTS_REVISER_VERSION)

$(GO_ADD_LICENSE):  $(call tool_version_file,$(GO_ADD_LICENSE),$(GO_ADD_LICENSE_VERSION))
	@echo "install target: $@"
	@GOBIN=$(abspath $(TOOLS_DIR)) go install github.com/google/addlicense@$(GO_ADD_LICENSE_VERSION)

$(MOCKGEN): $(call tool_version_file,$(MOCKGEN),$(MOCKGEN_VERSION))
	@echo "install target: $@"
	@GOBIN=$(abspath $(TOOLS_DIR)) go install go.uber.org/mock/mockgen@$(MOCKGEN_VERSION)

$(SETUP_ENVTEST): $(call tool_version_file,$(SETUP_ENVTEST),$(SETUP_ENVTEST_VERSION))
	@echo "install target: $@"
	@GOBIN=$(abspath $(TOOLS_DIR)) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VERSION)
	@$(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(TOOLS_DIR)

$(GOSEC): $(call tool_version_file,$(GOSEC),$(GOSEC_VERSION))
	@echo "install target: $@"
	@GOBIN=$(abspath $(TOOLS_DIR)) go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)

$(GOTESTSUM): $(call tool_version_file,$(GOTESTSUM),$(GOTESTSUM_VERSION))
	@echo "install target: $@"
	@GOBIN=$(abspath $(TOOLS_DIR)) go install gotest.tools/gotestsum@$(GOTESTSUM_VERSION)

.PHONY: create-tools clean-tools