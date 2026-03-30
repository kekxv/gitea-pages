# Deployer Dockerfile for Gitea Pages
# Multi-stage build for minimal image, non-root user

# Build stage
FROM golang:1.26-alpine AS builder

# Install build dependencies for sqlite3
RUN apk add --no-cache gcc musl-dev

WORKDIR /build

# Copy go.mod and go.sum first for dependency caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source files
COPY *.go ./

# Build binary with static linking for sqlite3
RUN CGO_ENABLED=1 go build -ldflags="-s -w -extldflags '-static'" -o deployer .

# Final stage
FROM alpine:3.21

# Security: Create non-privileged user
ARG PUID=1000
ARG PGID=1000

RUN addgroup -g ${PGID} -S pagesgroup && \
    adduser -u ${PUID} -S pagesuser -G pagesgroup -h /var/www/pages && \
    # Install git, openssh for SSH-based private repo access, and wget for health check
    apk add --no-cache git openssh-client wget && \
    # Create necessary directories including SSH directory and data directory
    mkdir -p /var/www/pages /var/www/pages/.ssh /var/lib/deployer /var/log && \
    # Set ownership
    chown -R pagesuser:pagesgroup /var/www/pages /var/lib/deployer /var/log && \
    chmod 700 /var/www/pages/.ssh

# Copy binary from builder
COPY --from=builder /build/deployer /usr/local/bin/deployer

# Set binary permissions
RUN chmod 755 /usr/local/bin/deployer && \
    chown pagesuser:pagesgroup /usr/local/bin/deployer

# Switch to non-privileged user
USER pagesuser

# Environment defaults
ENV WEBHOOK_PORT=8080 \
    DOMAIN=yourdomain.com \
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