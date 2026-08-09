# Nginx image for Gitea Pages.  The server runs as an unprivileged user and
# needs only the writable tmpfs mounts declared by docker-compose.yml.
FROM nginx:alpine

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
    sed "s/__PAGES_DOMAIN_REGEX__/${domain_regex}/g" /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf && \
    rm /etc/nginx/nginx.conf.template /etc/nginx/conf.d/default.conf

USER pagesuser

EXPOSE 8080 8081

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8081/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
