# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
# SPDX-License-Identifier: Apache-2.0
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
TOOLS_MOD                   := $(TOOLS_DIR)/go.mod
GO_TOOL                     := go tool -modfile=$(TOOLS_MOD)
ENVTEST_K8S_VERSION         ?= 1.32.0

GCI_OPT                     ?= -s standard -s default -s "prefix($(shell go list -m))" --skip-generated

ifneq ($(strip $(shell git status --porcelain 2>/dev/null)),)
	EFFECTIVE_VERSION := $(EFFECTIVE_VERSION)-dirty
endif
IMAGE_TAG                   := $(EFFECTIVE_VERSION)

$(TOOLS_DIR):
	@mkdir -p $(TOOLS_DIR)

#########################################
# Targets                               #
#########################################
.DEFAULT_GOAL := all
all: check build test envtest

.PHONY: verify
verify: check check-go-fix test envtest sast

.PHONY: verify-extended
verify-extended: verify sast-report

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

PROVIDER_LOCAL_DIR      := $(REPO_ROOT)/example/provider-local

.PHONY: deploy
deploy:
	@# --- Prerequisites ---
	@kubectl config current-context | grep -q "kind-gardener-local" || \
		{ echo "Error: current kubectl context is not kind-gardener-local"; exit 1; }
	@kubectl get shoot local -n garden-local > /dev/null 2>&1 || \
		{ echo "Error: shoot 'local' not found in namespace 'garden-local'"; exit 1; }
	@# --- Dex/LDAP infrastructure ---
	@if [ ! -f "$(PROVIDER_LOCAL_DIR)/certs/ca.pem" ] || [ ! -f "$(PROVIDER_LOCAL_DIR)/certs/dex.pem" ]; then \
		echo "Generating certificates..."; \
		$(PROVIDER_LOCAL_DIR)/00-setup_certs.sh; \
	fi
	@if [ ! -f "$(PROVIDER_LOCAL_DIR)/configs/local.ldif" ]; then \
		echo "Generating local.ldif with default passwords..."; \
		if command -v slappasswd > /dev/null 2>&1; then \
			op_hash=$$(slappasswd -s admin); \
			pv_hash=$$(slappasswd -s admin); \
			sed "s|^userpassword: # TODO: Add operator password.*|userpassword: $$op_hash|" \
				$(PROVIDER_LOCAL_DIR)/configs/local.ldif.tmpl | \
			sed "s|^userpassword: # TODO: Add project-viewer password.*|userpassword: $$pv_hash|" \
				> $(PROVIDER_LOCAL_DIR)/configs/local.ldif; \
		else \
			sed "s|^userpassword: # TODO: Add operator password.*|userpassword: admin|" \
				$(PROVIDER_LOCAL_DIR)/configs/local.ldif.tmpl | \
			sed "s|^userpassword: # TODO: Add project-viewer password.*|userpassword: admin|" \
				> $(PROVIDER_LOCAL_DIR)/configs/local.ldif; \
		fi \
	fi
	@if ! docker inspect dexidp --format '{{.State.Running}}' 2>/dev/null | grep -q true || \
	    ! docker inspect ldap --format '{{.State.Running}}' 2>/dev/null | grep -q true; then \
		echo "Starting Dex IdP and OpenLDAP..."; \
		cd $(PROVIDER_LOCAL_DIR) && docker compose down 2>/dev/null; \
		docker volume rm provider-local_ldap provider-local_sqlite3 -f 2>/dev/null; \
		cd $(PROVIDER_LOCAL_DIR) && docker compose up -d; \
		echo "Waiting for dexidp..."; \
		while ! docker inspect dexidp --format '{{.State.Running}}' 2>/dev/null | grep -q true; do sleep 1; done; \
		echo "Waiting for ldap..."; \
		while ! docker inspect ldap --format '{{.State.Running}}' 2>/dev/null | grep -q true; do sleep 1; done; \
		echo "Dex and LDAP are running."; \
	else \
		echo "Dex and LDAP are already running."; \
	fi
	@# --- Build and load image ---
	@KIND_ARCH=$$(docker image inspect $$(docker inspect gardener-local-control-plane -f '{{.Config.Image}}') -f '{{.Architecture}}' 2>/dev/null || echo "amd64"); \
		echo "Building image for linux/$${KIND_ARCH}..."; \
		docker build --platform "linux/$${KIND_ARCH}" \
			--tag $(IMAGE_REPOSITORY):latest \
			--tag $(IMAGE_REPOSITORY):$(IMAGE_TAG) \
			-f Dockerfile --target oidc-apps-controller $(REPO_ROOT); \
		kind load docker-image $(IMAGE_REPOSITORY):latest $(IMAGE_REPOSITORY):$(IMAGE_TAG) --name gardener-local
	@# --- Apply via kustomize ---
	@kubectl annotate seed local oidc-apps.extensions.gardener.cloud/client-name=local --overwrite
	@echo "Applying kustomize manifests..."
	@IMAGE_REPOSITORY=$(IMAGE_REPOSITORY) IMAGE_TAG=$(IMAGE_TAG) \
		kustomize build --enable-alpha-plugins --enable-exec \
		$(PROVIDER_LOCAL_DIR)/kustomize | kubectl apply --server-side --force-conflicts -f -
	@echo "Deploy complete."

.PHONY: deploy-check
deploy-check:
	@$(PROVIDER_LOCAL_DIR)/01-check_environment.sh


#####################################################################
# Rules for verification, formatting, linting, testing and cleaning #
#####################################################################
.PHONY: tidy
tidy:
	@go mod tidy
	@cd $(TOOLS_DIR) && go mod tidy

.PHONY: gci
gci: tidy
	@echo "Running gci..."
	@$(GO_TOOL) gci write $(GCI_OPT) $(SRC_DIRS)

.PHONY: fmt
fmt: tidy
	@echo "Running $@..."
	@$(GO_TOOL) golangci-lint fmt \
    	--config=$(REPO_ROOT)/.golangci.yaml \
    	$(SRC_DIRS)

.PHONY: check-go-fix
check-go-fix: tidy
	@echo "Running go fix..."
	@go fix $(SRC_DIRS)/...
	@if [ -n "$$(git status --porcelain $(SRC_DIRS))" ]; then \
		echo "Error: go fix produced changes. Please run 'go fix ./...' and commit the changes."; \
		git --no-pager diff; \
		exit 1; \
	fi

.PHONY: check
check: tidy fmt gci lint

.PHONY: lint
lint: tidy
	@echo "Running $@..."
	@$(GO_TOOL) golangci-lint run \
	 	--config=$(REPO_ROOT)/.golangci.yaml \
		$(SRC_DIRS)

.PHONY: build
build: tidy
	@CGO_ENABLED=0 go build -ldflags="$(LD_FLAGS)" \
	  	-o $(REPO_ROOT)/build/$(NAME) $(REPO_ROOT)/cmd/main.go

.PHONY: clean
clean:
	@echo "Running $@..."
	@rm -f $(REPO_ROOT)/build/$(NAME)
	@rm -f $(REPO_ROOT)/gosec-report.sarif
	@$(GO_TOOL) setup-envtest cleanup --bin-dir=$(TOOLS_DIR)


.PHONY: test
test: tidy
	@go generate $(SRC_DIRS)
	@$(GO_TOOL) gotestsum --format-hide-empty-pkg $(REPO_ROOT)/cmd/... $(REPO_ROOT)/pkg/...

.PHONY: envtest
envtest: tidy
	@KUBEBUILDER_ASSETS=$(shell \
		$(GO_TOOL) setup-envtest \
		use $(ENVTEST_K8S_VERSION) \
		--bin-dir=$(TOOLS_DIR) \
		-p path 2>/dev/null || true) \
		$(GO_TOOL) gotestsum \
			--format-hide-empty-pkg \
			$(REPO_ROOT)/test/... \
			--ginkgo.v \
			-timeout 10m

.PHONY: add-license-headers
add-license-headers: tidy
	@$(REPO_ROOT)/hack/add-license-header.sh

.PHONY: govulncheck
govulncheck: tidy
	@$(GO_TOOL) govulncheck $(REPO_ROOT)/...

.PHONY: sast
sast: tidy $(GOSEC)
	@$(REPO_ROOT)/hack/sast.sh

.PHONY: sast-report
sast-report: tidy $(GOSEC)
	@$(REPO_ROOT)/hack/sast.sh --gosec-report true
