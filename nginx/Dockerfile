# Nginx image for Gitea Pages.  The server runs as an unprivileged user and
# needs only the writable tmpfs mounts declared by docker-compose.yml.
FROM nginx:1.27.5-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

ARG PUID=1000
ARG PGID=1000
ARG PAGES_DOMAIN

RUN mkdir -p /var/www/pages /var/cache/nginx && \
    addgroup -g "${PGID}" -S pagesgroup && \
    adduser -u "${PUID}" -S pagesuser -G pagesgroup -h /var/www/pages && \
    chown -R pagesuser:pagesgroup /var/www/pages /var/cache/nginx

# Keep one marker in the checked-in configuration and bind it to a validated
# literal domain during the build.  The final image contains no template.
COPY nginx.conf /etc/nginx/nginx.conf.template
RUN case "$PAGES_DOMAIN" in \
      ''|*[!A-Za-z0-9.-]*|.*|*..*|*.) exit 1 ;; \
    esac && \
    domain_regex="$(printf '%s' "$PAGES_DOMAIN" | sed 's/\./\\\\./g')" && \
    sed -e "s/__PAGES_DOMAIN_REGEX__/${domain_regex}/g" \
        -e "s/__PAGES_DOMAIN_LITERAL__/${PAGES_DOMAIN}/g" \
        /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf && \
    rm /etc/nginx/nginx.conf.template /etc/nginx/conf.d/default.conf

USER pagesuser

EXPOSE 8080 8081

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8081/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
