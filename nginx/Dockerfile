# Nginx image for Gitea Pages.  The server runs as an unprivileged user and
# needs only the writable tmpfs mounts declared by docker-compose.yml.
FROM nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de

ARG PUID=1000
ARG PGID=1000

RUN mkdir -p /var/www/pages /var/cache/nginx && \
    addgroup -g "${PGID}" -S pagesgroup && \
    adduser -u "${PUID}" -S pagesuser -G pagesgroup -h /var/www/pages && \
    chown -R pagesuser:pagesgroup /var/www/pages /var/cache/nginx

# Render the domain-specific virtual hosts at container startup. This keeps a
# pre-built image reusable across installations with different Pages domains.
COPY nginx.conf /etc/nginx/nginx.conf.template
COPY start-nginx.sh /usr/local/bin/start-nginx.sh
RUN chmod 755 /usr/local/bin/start-nginx.sh && \
    rm /etc/nginx/conf.d/default.conf

USER pagesuser

EXPOSE 8080 8081

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8081/health || exit 1

CMD ["/usr/local/bin/start-nginx.sh"]
