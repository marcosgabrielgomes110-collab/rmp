# RMP — Remote Machine Protocol
# Makefile for building, testing, installing and packaging the `rmp` binary.

SHELL := /bin/sh

# ---- Configuration ---------------------------------------------------------

CARGO      ?= cargo
PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
DESTDIR    ?=

# Optional cross-compilation target, e.g. TARGET=x86_64-unknown-linux-musl
TARGET     ?=
TARGET_ARG  := $(if $(TARGET),--target $(TARGET),)
TARGET_DIR := $(if $(TARGET),$(TARGET)/,)

BIN_NAME   := rmp
ROOT       := $(CURDIR)
RELEASE    := $(ROOT)/target/$(TARGET_DIR)release/$(BIN_NAME)

VERSION    := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
ifeq ($(VERSION),)
VERSION    := 0.0.0
endif

DIST_DIR   := $(ROOT)/dist
DIST_NAME  := rmp-$(VERSION)-$(if $(TARGET),$(TARGET),$(shell uname -s | tr 'A-Z' 'a-z'))-$(shell uname -m)

# ---- Phony targets ---------------------------------------------------------

.PHONY: all help release debug check test clippy fmt fmt-check clean \
        install uninstall dist run-init run-serve run-connect print-version

all: release

help: ## Show this help
	@printf 'RMP build targets:\n\n'
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@printf '\nVariables: PREFIX=%s BINDIR=%s DESTDIR=%s TARGET=%s\n' \
		"$(PREFIX)" "$(BINDIR)" "$(DESTDIR)" "$(TARGET)"

print-version: ## Print the project version
	@echo $(VERSION)

# ---- Build -----------------------------------------------------------------

release: ## Build the optimized `rmp` binary (LTO + strip)
	$(CARGO) build --release --locked $(TARGET_ARG)
	@echo "Built: $(RELEASE)"
	@ls -lh $(RELEASE)

debug: ## Build the debug binary
	$(CARGO) build $(TARGET_ARG)

# ---- Quality ---------------------------------------------------------------

check: ## Type-check the whole workspace
	$(CARGO) check --all-targets $(TARGET_ARG)

test: ## Run the full test suite (unit + end-to-end)
	$(CARGO) test --all $(TARGET_ARG)

clippy: ## Lint with clippy (warnings are errors)
	$(CARGO) clippy --all-targets -- -D warnings

fmt: ## Format the code
	$(CARGO) fmt --all

fmt-check: ## Verify formatting without changing files
	$(CARGO) fmt --all -- --check

# ---- Install ---------------------------------------------------------------

install: release ## Install the binary into $(BINDIR)
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 "$(RELEASE)" "$(DESTDIR)$(BINDIR)/$(BIN_NAME)"
	@echo "Installed $(DESTDIR)$(BINDIR)/$(BIN_NAME)"

uninstall: ## Remove the installed binary
	rm -f "$(DESTDIR)$(BINDIR)/$(BIN_NAME)"
	@echo "Removed $(DESTDIR)$(BINDIR)/$(BIN_NAME)"

# ---- Packaging -------------------------------------------------------------

dist: release ## Package the binary and docs into dist/
	@rm -rf "$(DIST_DIR)/$(DIST_NAME)"
	@mkdir -p "$(DIST_DIR)/$(DIST_NAME)"
	@install -m 0755 "$(RELEASE)" "$(DIST_DIR)/$(DIST_NAME)/$(BIN_NAME)"
	@cp README.md "$(DIST_DIR)/$(DIST_NAME)/"
	@cp -r docs "$(DIST_DIR)/$(DIST_NAME)/docs"
	@[ -f LICENSE ] && cp LICENSE "$(DIST_DIR)/$(DIST_NAME)/" || true
	@cd "$(DIST_DIR)" && tar -czf "$(DIST_NAME).tar.gz" "$(DIST_NAME)" \
		&& rm -rf "$(DIST_NAME)"
	@echo "Package: $(DIST_DIR)/$(DIST_NAME).tar.gz"
	@ls -lh "$(DIST_DIR)/$(DIST_NAME).tar.gz"

# ---- Convenience -----------------------------------------------------------

update: ## Check the latest GitHub release and update the installed rmp
	./scripts/update.sh

REMOTE ?= user@host:2222
# Extra flags, e.g. ARGS="--system" or ARGS="--dir ./state"
ARGS   ?=

run-init: ## Run `rmp init` (add ARGS="--system" for system dirs)
	$(CARGO) run --release -- init $(ARGS)

run-serve: ## Run `rmp serve`
	$(CARGO) run --release -- serve $(ARGS)

run-connect: ## Run `rmp connect` (REMOTE=user@host, ARGS="--accept-new")
	$(CARGO) run --release -- connect "$(REMOTE)" $(ARGS)

# ---- Cleanup ---------------------------------------------------------------

clean: ## Remove build artifacts
	$(CARGO) clean
	rm -rf "$(DIST_DIR)"
