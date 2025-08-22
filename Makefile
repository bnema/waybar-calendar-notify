# Makefile for waybar-calendar-notify

# Default values
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go variables
BINARY_NAME = waybar-calendar-notify
MAIN_PACKAGE = .
LDFLAGS = -ldflags "-X main.Version=$(VERSION) \
                   -X main.CommitHash=$(COMMIT_HASH) \
                   -X main.BuildTime=$(BUILD_TIME)"

# Build directories
BUILD_DIR = ./dist
LOCAL_BIN = ./bin

.PHONY: help build build-local clean install test lint fmt vet deps dev-build security-audit test-security build-secure build-obfuscated check-garble generate-secrets test-obfuscation test-obfuscation-comprehensive clean-obfuscated

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
	go build $(LDFLAGS) -o $(LOCAL_BIN)/$(BINARY_NAME) $(MAIN_PACKAGE)

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

test: ## Run tests
	@echo "Running tests..."
	go test ./...

test-verbose: ## Run tests with verbose output
	@echo "Running tests with verbose output..."
	go test -v ./...

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
release: clean test lint build ## Full release build (clean, test, lint, build)
	@echo "Release build complete!"
	@echo "Binary: $(BUILD_DIR)/$(BINARY_NAME)"
	@echo "Version: $(VERSION)"

security-audit: ## Run security audit tools
	@echo "Running security audit..."
	@which nancy >/dev/null 2>&1 || echo "Warning: nancy not installed (go install github.com/sonatypecommunity/nancy@latest)"
	@which gosec >/dev/null 2>&1 || echo "Warning: gosec not installed (go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest)"
	-go list -json -deps | nancy sleuth 2>/dev/null || echo "Nancy audit completed"
	-gosec -fmt=json -out=security-report.json ./... 2>/dev/null || echo "Gosec audit completed"

test-security: ## Run security-specific tests
	@echo "Running security tests..."
	go test -v ./internal/security/... -cover

build-secure: ## Build with security hardening flags
	@echo "Building $(BINARY_NAME) with security hardening..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -trimpath \
		-ldflags="-s -w -extldflags=-static $(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)

check: fmt vet lint test test-security ## Run all checks (format, vet, lint, test, security)
	@echo "All checks passed!"

security-check: security-audit test-security ## Run comprehensive security checks
	@echo "Security checks completed!"

# Obfuscation targets
check-garble: ## Check if garble is installed
	@echo "Checking for garble..."
	@which garble >/dev/null 2>&1 || (echo "ERROR: garble not found. Install with: go install mvdan.cc/garble@latest" && exit 1)
	@echo "✓ garble found: $$(garble --version 2>/dev/null || echo 'version unknown')"

generate-secrets: ## Generate embedded secrets from client_secrets_device_oauth.json
	@echo "Generating embedded secrets..."
	@if [ ! -f client_secrets_device_oauth.json ]; then \
		echo "ERROR: client_secrets_device_oauth.json not found"; \
		echo "This file is required to generate embedded secrets"; \
		exit 1; \
	fi
	@echo "Encoding client secrets with XOR obfuscation..."
	@go run scripts/encode-secrets.go client_secrets_device_oauth.json > internal/calendar/embedded_secrets_data.go
	@echo "✓ Generated embedded secrets data"

build-obfuscated: check-garble ## Build obfuscated binary with embedded secrets
	@echo "Building obfuscated binary..."
	@chmod +x scripts/build-obfuscated.sh
	@./scripts/build-obfuscated.sh

test-obfuscation: ## Test that secrets are properly obfuscated in binary (basic)
	@echo "Running basic obfuscation tests..."
	@if [ ! -f waybar-calendar-notify-obfuscated ]; then \
		echo "ERROR: waybar-calendar-notify-obfuscated not found. Run 'make build-obfuscated' first"; \
		exit 1; \
	fi
	@echo "Checking for obvious string leaks..."
	@LEAKED=0; \
	if strings waybar-calendar-notify-obfuscated 2>/dev/null | grep -qi "client_id" 2>/dev/null; then \
		echo "⚠ WARNING: 'client_id' string found in binary!"; \
		LEAKED=1; \
	fi; \
	if strings waybar-calendar-notify-obfuscated 2>/dev/null | grep -qi "client_secret" 2>/dev/null; then \
		echo "⚠ WARNING: 'client_secret' string found in binary!"; \
		LEAKED=1; \
	fi; \
	if strings waybar-calendar-notify-obfuscated 2>/dev/null | grep -qE "[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com" 2>/dev/null; then \
		echo "⚠ WARNING: Client ID pattern found in binary!"; \
		LEAKED=1; \
	fi; \
	if strings waybar-calendar-notify-obfuscated 2>/dev/null | grep -q "GOCSPX-" 2>/dev/null; then \
		echo "⚠ WARNING: Client secret pattern found in binary!"; \
		LEAKED=1; \
	fi; \
	if [ $$LEAKED -eq 0 ]; then \
		echo "✓ No obvious credential leaks detected"; \
		echo "✓ Binary size: $$(du -h waybar-calendar-notify-obfuscated | cut -f1)"; \
		echo "✓ Basic obfuscation tests passed"; \
	else \
		echo "❌ Potential credential leaks detected!"; \
		exit 1; \
	fi

test-obfuscation-comprehensive: ## Run comprehensive obfuscation analysis
	@echo "Running comprehensive obfuscation analysis..."
	@chmod +x scripts/test-obfuscation.sh
	@./scripts/test-obfuscation.sh

test-obfuscated-runtime: ## Test that obfuscated binary runs correctly
	@echo "Testing obfuscated binary runtime..."
	@if [ ! -f waybar-calendar-notify-obfuscated ]; then \
		echo "ERROR: waybar-calendar-notify-obfuscated not found. Run 'make build-obfuscated' first"; \
		exit 1; \
	fi
	@echo "Testing auth status command..."
	@./waybar-calendar-notify-obfuscated auth --status || echo "Auth status test completed (may fail if not authenticated)"
	@echo "Testing help command..."
	@./waybar-calendar-notify-obfuscated --help >/dev/null
	@echo "✓ Basic runtime tests passed"

clean-obfuscated: ## Clean obfuscation artifacts
	@echo "Cleaning obfuscation artifacts..."
	@rm -f waybar-calendar-notify-obfuscated
	@rm -f waybar-calendar-notify-obfuscated.original
	@rm -f .garble-seed
	@rm -f .build-timestamp
	@rm -f internal/calendar/embedded_secrets.go.bak
	@rm -f internal/calendar/embedded_secrets_temp.go
	@rm -f internal/calendar/embedded_secrets_data.go
	@rm -rf $(HOME)/.cache/garble-waybar
	@echo "✓ Cleaned obfuscation artifacts"

# Full obfuscation workflow
build-obfuscated-release: clean-obfuscated check test lint build-obfuscated test-obfuscation-comprehensive test-obfuscated-runtime ## Complete obfuscated release build
	@echo ""
	@echo "=================================================="
	@echo "Obfuscated Release Build Complete!"
	@echo "=================================================="
	@echo "✓ Binary: waybar-calendar-notify-obfuscated"
	@echo "✓ Size: $$(du -h waybar-calendar-notify-obfuscated | cut -f1)"
	@echo "✓ All tests passed"
	@echo "✓ Obfuscation verified"
	@echo "✓ Ready for distribution"
	@echo ""
	@echo "Users will not need client_secrets_device_oauth.json"
	@echo "The OAuth credentials are embedded and obfuscated in the binary"

help-obfuscation: ## Show help for obfuscation targets
	@echo "Obfuscation Build Targets:"
	@echo ""
	@echo "  check-garble         - Check if garble is installed"
	@echo "  generate-secrets     - Generate embedded secrets from client_secrets_device_oauth.json"  
	@echo "  build-obfuscated     - Build obfuscated binary with embedded secrets"
	@echo "  test-obfuscation     - Basic obfuscation effectiveness tests"
	@echo "  test-obfuscation-comprehensive - Comprehensive obfuscation analysis"
	@echo "  test-obfuscated-runtime - Test obfuscated binary runtime"
	@echo "  clean-obfuscated     - Clean obfuscation artifacts"
	@echo "  build-obfuscated-release - Complete obfuscated release workflow"
	@echo ""
	@echo "Prerequisites:"
	@echo "  1. Install garble: go install mvdan.cc/garble@latest"
	@echo "  2. Ensure client_secrets_device_oauth.json exists in project root"
	@echo ""
	@echo "Usage:"
	@echo "  make build-obfuscated-release  # Full build and test"
	@echo "  make build-obfuscated          # Quick build only"