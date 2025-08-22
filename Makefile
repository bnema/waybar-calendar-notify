# Makefile for waybar-calendar-notify

# Default values
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
RELAY_URL ?= https://gcal-oauth-relay.bnema.dev
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go variables
BINARY_NAME = waybar-calendar-notify
MAIN_PACKAGE = .
LDFLAGS = -ldflags "-X github.com/bnema/waybar-calendar-notify/internal/calendar.RelayURL=$(RELAY_URL) \
                   -X main.Version=$(VERSION) \
                   -X main.CommitHash=$(COMMIT_HASH) \
                   -X main.BuildTime=$(BUILD_TIME)"

# Build directories
BUILD_DIR = ./dist
LOCAL_BIN = ./bin

.PHONY: help build build-local clean install test lint fmt vet deps dev-build security-audit test-security build-secure

help: ## Show this help message
	@echo "waybar-calendar-notify Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build production binary with injected values
	@echo "Building $(BINARY_NAME) v$(VERSION) for production..."
	@echo "Relay URL: $(RELAY_URL)"
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)

build-local: ## Build local development binary
	@echo "Building $(BINARY_NAME) for local development..."
	@mkdir -p $(LOCAL_BIN)
	go build $(LDFLAGS) -o $(LOCAL_BIN)/$(BINARY_NAME) $(MAIN_PACKAGE)

dev-build: ## Build with development relay URL
	@echo "Building for development with local relay..."
	@mkdir -p $(LOCAL_BIN)
	RELAY_URL=http://localhost:8080 $(MAKE) build-local

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
	@echo "Relay URL: $(RELAY_URL)"

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