# Deployer Dockerfile for Gitea Pages
# Multi-stage build for minimal image, non-root user

# Build stage
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

WORKDIR /build

# Allow restricted build environments to select an approved Go module proxy.
ARG GOPROXY=https://proxy.golang.org,direct

# Copy go.mod and go.sum first for dependency caching
COPY go.mod go.sum ./
RUN GOPROXY=${GOPROXY} go mod download

# Copy source files
COPY *.go ./

# Build a pure-Go binary; the SQLite driver does not require CGO.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o deployer .

# Final stage
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

# Security: Create non-privileged user
ARG PUID=1000
ARG PGID=1000

RUN addgroup -g ${PGID} -S pagesgroup && \
    adduser -u ${PUID} -S pagesuser -G pagesgroup -h /var/www/pages && \
    # HTTPS-only Git deployment and health checks
    apk add --no-cache git wget && \
    mkdir -p /var/www/pages /var/lib/deployer /var/log && \
    # Set ownership
    chown -R pagesuser:pagesgroup /var/www/pages /var/lib/deployer /var/log

# Copy binary from builder
COPY --from=builder /build/deployer /usr/local/bin/deployer
COPY git-askpass.sh /usr/local/lib/gitea-pages/git-askpass

# Set binary permissions
RUN chmod 755 /usr/local/bin/deployer && \
    chown pagesuser:pagesgroup /usr/local/bin/deployer && \
    chmod 755 /usr/local/lib/gitea-pages/git-askpass && \
    chown root:root /usr/local/lib/gitea-pages/git-askpass

# Switch to non-privileged user
USER pagesuser

# Environment defaults
ENV WEBHOOK_PORT=8080 \
    DOMAIN=pages.yourdomain.com \
    PAGES_DATA_DIR=/var/www/pages \
    DEPLOYER_DATA_DIR=/var/lib/deployer \
    MAX_SITE_SIZE_MB=100

# Expose webhook port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/health || exit 1

# Start deployer
CMD ["deployer"]
