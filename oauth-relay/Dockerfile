# Build stage - security hardened
FROM golang:1.24-alpine AS builder

# Install dependencies for building and verification
RUN apk add --no-cache git ca-certificates file

WORKDIR /build

# Copy and verify dependencies first (better layer caching)
COPY go.mod go.sum* ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build with comprehensive security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -extldflags '-static'" \
    -trimpath \
    -tags "netgo,osusergo" \
    -o oauth-relay .

# Verify the binary is statically linked  
RUN file oauth-relay

# Runtime stage - distroless for minimal attack surface
FROM gcr.io/distroless/static:nonroot

# Use non-root user (uid 65532)
USER 65532:65532

# Copy ca-certificates and binary
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/oauth-relay /oauth-relay

# Expose port (non-privileged)
EXPOSE 8080

# Health check with distroless-compatible command
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/oauth-relay", "-health"]

# Run the binary
ENTRYPOINT ["/oauth-relay"]