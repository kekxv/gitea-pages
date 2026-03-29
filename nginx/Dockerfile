# Nginx Dockerfile for Gitea Pages
# Security-hardened, non-root user, minimal image

FROM nginx:alpine AS builder

# Final stage
FROM nginx:alpine

# Build arguments for user/group IDs
ARG PUID=1000
ARG PGID=1000

# Security: Create non-privileged user
RUN addgroup -g ${PGID} -S pagesgroup && \
    adduser -u ${PUID} -S pagesuser -G pagesgroup -h /var/www/pages && \
    # Create necessary directories with correct permissions
    mkdir -p /var/www/pages /var/log/nginx /var/run/nginx /var/cache/nginx && \
    # Set ownership
    chown -R pagesuser:pagesgroup /var/www/pages /var/log/nginx /var/run/nginx /var/cache/nginx && \
    # Create error page directory
    mkdir -p /var/www/pages/_error && \
    # Create default 404 page
    echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>' > /var/www/pages/_error/404.html && \
    chown pagesuser:pagesgroup /var/www/pages/_error/404.html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Security: Remove default nginx config
RUN rm -f /etc/nginx/conf.d/default.conf

# Security: Set proper permissions on nginx config
RUN chown pagesuser:pagesgroup /etc/nginx/nginx.conf

# Switch to non-privileged user
USER pagesuser

# Expose HTTP port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8081/health || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]