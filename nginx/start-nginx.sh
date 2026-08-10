#!/bin/sh
set -eu

pages_domain=${PAGES_DOMAIN:-}
case "$pages_domain" in
    ''|*[!A-Za-z0-9.-]*|.*|*..*|*.)
        echo 'PAGES_DOMAIN must be a non-empty DNS domain name' >&2
        exit 1
        ;;
esac

domain_regex=$(printf '%s' "$pages_domain" | sed 's/\./\\\\./g')
sed -e "s/__PAGES_DOMAIN_REGEX__/${domain_regex}/g" \
    -e "s/__PAGES_DOMAIN_LITERAL__/${pages_domain}/g" \
    /etc/nginx/nginx.conf.template > /tmp/nginx.conf

if [ "$#" -gt 0 ]; then
    exec nginx -c /tmp/nginx.conf "$@"
fi

exec nginx -c /tmp/nginx.conf -g 'daemon off;'
