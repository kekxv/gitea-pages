#!/usr/bin/env bash
set -euo pipefail

image="gitea-pages-nginx:test"
container="gitea-pages-nginx-test-$$"
pages_dir="$(mktemp -d "$PWD/.nginx-pages.XXXXXX")"
secret_dir="$(mktemp -d "$PWD/.nginx-secrets.XXXXXX")"
host_port="$(shuf -i 20000-29999 -n 1)"
upstream_pid=""
webhook_body="$secret_dir/webhook-body"
webhook_capture="$secret_dir/webhook-capture"
oversized_body="$secret_dir/oversized-body"
rate_statuses="$secret_dir/rate-statuses"

cleanup() {
    local status=$?
    trap - EXIT
    docker rm -f "$container" >/dev/null 2>&1 || true
    if [[ -n "$upstream_pid" ]]; then
        kill "$upstream_pid" >/dev/null 2>&1 || true
        wait "$upstream_pid" >/dev/null 2>&1 || true
    fi
    rm -rf "$pages_dir"
    rm -rf "$secret_dir"
    exit "$status"
}
trap cleanup EXIT

mkdir -p "$pages_dir/alice/_root" "$pages_dir/alice/project"
chmod 755 "$pages_dir"
printf 'Alice root site\n' > "$pages_dir/alice/_root/index.html"
printf 'Alice project site\n' > "$pages_dir/alice/project/index.html"

grep -Eq '^FROM nginx:1\.29-alpine@sha256:[0-9a-f]{64}$' nginx/Dockerfile
# A generic release image must accept its Pages domain at container startup,
# not bind every consumer to the domain present when the image was built.
docker build -t "${image}-default-domain" ./nginx
default_nginx="$(docker run --rm --network none --add-host deployer:127.0.0.1 \
    -e PAGES_DOMAIN=pages.invalid "${image}-default-domain" \
    /usr/local/bin/start-nginx.sh -T 2>&1)"
grep -Fq 'pages.invalid' <<<"$default_nginx"
# DOMAIN is the complete Pages domain.  Existing installations use values such
# as pages.example.com, which must continue to route alice.pages.example.com.
docker build -t "$image" ./nginx

docker run --rm --network none --read-only --user 1000:1000 --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --add-host deployer:127.0.0.1 \
    -e PAGES_DOMAIN=pages.example.com \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 \
    --tmpfs /var/cache/nginx:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 \
    "$image" /usr/local/bin/start-nginx.sh -t

rendered_nginx="$(docker run --rm --network none --read-only --user 1000:1000 --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --add-host deployer:127.0.0.1 \
    -e PAGES_DOMAIN=pages.example.com \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 \
    --tmpfs /var/cache/nginx:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 \
    "$image" /usr/local/bin/start-nginx.sh -T 2>&1)"
grep -Fq 'client_max_body_size 1m;' <<<"$rendered_nginx"
grep -Fq 'limit_req zone=webhook' <<<"$rendered_nginx"

docker run -d --name "$container" --read-only --user 1000:1000 --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --add-host deployer:host-gateway \
    -e PAGES_DOMAIN=pages.example.com \
    -p "127.0.0.1:${host_port}:8080" \
    -v "$pages_dir:/var/www/pages:ro" \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 \
    --tmpfs /var/cache/nginx:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 \
    "$image" >/dev/null

for _ in $(seq 1 30); do
    if curl --silent --fail --max-time 1 -H 'Host: alice.pages.example.com' \
        "http://127.0.0.1:${host_port}/" >/dev/null; then
        break
    fi
    sleep 0.1
done

assert_status() {
    local expected="$1"
    local host="$2"
    local path="$3"
    local actual
    actual="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 \
        -H "Host: ${host}" "http://127.0.0.1:${host_port}${path}")"
    test "$actual" = "$expected"
}

test "$(curl --silent --fail -H 'Host: alice.pages.example.com' "http://127.0.0.1:${host_port}/")" = 'Alice root site'
test "$(curl --silent --fail -H 'Host: alice.pages.example.com' "http://127.0.0.1:${host_port}/project/index.html")" = 'Alice project site'
assert_status 421 alice.pages.attacker.com /
assert_status 421 alice.pages.example.com.attacker.com /
assert_status 403 alice.pages.example.com /.hidden
assert_status 403 alice.pages.example.com /_root
assert_status 405 pages.example.com /webhook

python3 - "$webhook_capture" >/dev/null 2>&1 <<'PY' &
import http.server
import pathlib
import sys

capture = pathlib.Path(sys.argv[1])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        payload = self.rfile.read(int(self.headers["Content-Length"]))
        capture.write_bytes(payload)
        self.send_response(204)
        self.end_headers()

    def log_message(self, format, *args):
        pass

http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
PY
upstream_pid=$!

for _ in $(seq 1 30); do
    if curl --silent --max-time 1 http://127.0.0.1:8080/ >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

printf 'signed webhook payload\nwith exact body bytes\n' > "$webhook_body"
test "$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
    -H 'Host: pages.example.com' -H 'Content-Type: application/json' \
    --data-binary @"$webhook_body" "http://127.0.0.1:${host_port}/webhook")" = '204'
cmp "$webhook_body" "$webhook_capture"

head -c 1048577 /dev/zero > "$oversized_body"
test "$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
    -H 'Host: pages.example.com' --data-binary @"$oversized_body" \
    "http://127.0.0.1:${host_port}/webhook")" = '413'

request_pids=()
for _ in $(seq 1 40); do
    (
        curl --silent --output /dev/null --write-out '%{http_code}\n' --max-time 5 \
            -H 'Host: pages.example.com' --data-binary 'rate-limit-test' \
            "http://127.0.0.1:${host_port}/webhook" >> "$rate_statuses"
    ) &
    request_pids+=("$!")
done
for request_pid in "${request_pids[@]}"; do
    wait "$request_pid"
done
grep -Fxq '429' "$rate_statuses"

printf '%032d\n' 0 > "$secret_dir/session"
printf '%032d\n' 0 > "$secret_dir/token-key"
printf 'oauth-client-secret\n' > "$secret_dir/oauth-client-secret"

deployer_compose="$(PAGES_DOMAIN=pages.example.com PAGES_GITEA_API_URL=https://gitea.example.com \
    PAGES_GITEA_PUBLIC_URL=https://gitea.example.com PAGES_OAUTH_CLIENT_ID=pages-client \
    PAGES_SESSION_SECRET_HOST_FILE="$secret_dir/session" \
    PAGES_TOKEN_ENCRYPTION_KEY_HOST_FILE="$secret_dir/token-key" \
    PAGES_OAUTH_CLIENT_SECRET_HOST_FILE="$secret_dir/oauth-client-secret" \
    docker compose config deployer)"
nginx_compose="$(PAGES_DOMAIN=pages.example.com PAGES_GITEA_API_URL=https://gitea.example.com \
    PAGES_GITEA_PUBLIC_URL=https://gitea.example.com PAGES_OAUTH_CLIENT_ID=pages-client \
    PAGES_SESSION_SECRET_HOST_FILE="$secret_dir/session" \
    PAGES_TOKEN_ENCRYPTION_KEY_HOST_FILE="$secret_dir/token-key" \
    PAGES_OAUTH_CLIENT_SECRET_HOST_FILE="$secret_dir/oauth-client-secret" \
    docker compose config nginx)"

! grep -Eq '^    ports:' <<<"$deployer_compose"
grep -Fq 'read_only: true' <<<"$deployer_compose"
grep -Fq 'ALL' <<<"$deployer_compose"
grep -Fq 'pids_limit:' <<<"$deployer_compose"
grep -Fq 'SESSION_SECRET_FILE: /run/secrets/gitea_pages_session_secret' <<<"$deployer_compose"
grep -Fq 'source: session_secret' <<<"$deployer_compose"
! grep -Fq '/dev/null' <<<"$deployer_compose"
grep -Fq 'OAUTH_REDIRECT_URL: https://pages.example.com/oauth/callback' <<<"$deployer_compose"
grep -Fq 'WEBHOOK_PUBLIC_URL: https://pages.example.com/webhook' <<<"$deployer_compose"
deployer_compose_default_public_url="$(PAGES_DOMAIN=pages.example.com PAGES_GITEA_API_URL=https://gitea.example.com \
    PAGES_OAUTH_CLIENT_ID=pages-client \
    PAGES_SESSION_SECRET_HOST_FILE="$secret_dir/session" \
    PAGES_TOKEN_ENCRYPTION_KEY_HOST_FILE="$secret_dir/token-key" \
    PAGES_OAUTH_CLIENT_SECRET_HOST_FILE="$secret_dir/oauth-client-secret" \
    docker compose config deployer)"
grep -Fq 'GITEA_PUBLIC_URL: https://gitea.example.com' <<<"$deployer_compose_default_public_url"
grep -Fq 'published: "80"' <<<"$nginx_compose"
grep -Fq 'target: 8080' <<<"$nginx_compose"
grep -Fq 'read_only: true' <<<"$nginx_compose"
grep -Fq 'ALL' <<<"$nginx_compose"
