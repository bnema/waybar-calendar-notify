# Makefile for waybar-calendar-notify

# Default values
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go variables
BINARY_NAME = waybar-calendar-notify
MAIN_PACKAGE = .
# Optional OAuth overrides (set these vars before calling make if you want to bake in credentials)
# WARNING: Embedding secrets in distributed binaries is insecure. Prefer user-provided env vars at runtime.
WAYBAR_GCAL_CLIENT_ID ?=
WAYBAR_GCAL_CLIENT_SECRET ?=

LDFLAGS = -ldflags "-X main.Version=$(VERSION) \
				   -X main.CommitHash=$(COMMIT_HASH) \
				   -X main.BuildTime=$(BUILD_TIME) \
				   $(if $(WAYBAR_GCAL_CLIENT_ID),-X github.com/bnema/waybar-calendar-notify/internal/calendar.GoogleOAuthClientID=$(WAYBAR_GCAL_CLIENT_ID)) \
				   $(if $(WAYBAR_GCAL_CLIENT_SECRET),-X github.com/bnema/waybar-calendar-notify/internal/calendar.GoogleOAuthClientSecret=$(WAYBAR_GCAL_CLIENT_SECRET))"

# Build directories
BUILD_DIR = ./dist
LOCAL_BIN = ./bin

.PHONY: help build build-local clean install lint fmt vet deps dev-build heck

help: ## Show this help message
	@echo "waybar-calendar-notify Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build production binary with injected values
	@echo "Building $(BINARY_NAME) v$(VERSION) for production..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)

build-local: ## Build local development binary
	@echo "Building $(BINARY_NAME) for local development..."
	@mkdir -p $(LOCAL_BIN)
	@if [ -f .env ]; then export $$(grep -v '^#' .env | xargs) && go build $(LDFLAGS) -o $(LOCAL_BIN)/$(BINARY_NAME) $(MAIN_PACKAGE); else go build $(LDFLAGS) -o $(LOCAL_BIN)/$(BINARY_NAME) $(MAIN_PACKAGE); fi

dev-build: ## Build for development
	@echo "Building for development..."
	@mkdir -p $(LOCAL_BIN)
	$(MAKE) build-local

install: build ## Install binary to GOPATH/bin
	@echo "Installing $(BINARY_NAME) to GOPATH/bin..."
	go install $(LDFLAGS) $(MAIN_PACKAGE)

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(LOCAL_BIN)
	go clean


lint: ## Run golangci-lint
	@echo "Running linter..."
	golangci-lint run

fmt: ## Format Go code
	@echo "Formatting code..."
	go fmt ./...

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Build for multiple platforms
build-all: ## Build for all supported platforms
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PACKAGE)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(MAIN_PACKAGE)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_PACKAGE)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_PACKAGE)

# Development helpers
run: build-local ## Build and run locally
	$(LOCAL_BIN)/$(BINARY_NAME)

run-auth: build-local ## Build and run auth command
	$(LOCAL_BIN)/$(BINARY_NAME) auth

run-sync: build-local ## Build and run sync command
	$(LOCAL_BIN)/$(BINARY_NAME) sync

# Version info
version: ## Show version information
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT_HASH)"
	@echo "Build Time: $(BUILD_TIME)"

# Release helpers
release: clean lint build ## Full release build (clean, lint, build)
	@echo "Release build complete!"
	@echo "Binary: $(BUILD_DIR)/$(BINARY_NAME)"
	@echo "Version: $(VERSION)"

check: fmt vet lint ## Run all checks (format, vet, lint)
	@echo "All checks passed!"