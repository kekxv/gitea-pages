#!/usr/bin/env bash
set -euo pipefail

image="gitea-pages-nginx:test"
container="gitea-pages-nginx-test-$$"
pages_dir="$(mktemp -d "$PWD/.nginx-pages.XXXXXX")"
secret_dir="$(mktemp -d "$PWD/.nginx-secrets.XXXXXX")"
host_port="$(shuf -i 20000-29999 -n 1)"

cleanup() {
    local status=$?
    trap - EXIT
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf "$pages_dir"
    rm -rf "$secret_dir"
    exit "$status"
}
trap cleanup EXIT

mkdir -p "$pages_dir/alice/_root" "$pages_dir/alice/project"
chmod 755 "$pages_dir"
printf 'Alice root site\n' > "$pages_dir/alice/_root/index.html"
printf 'Alice project site\n' > "$pages_dir/alice/project/index.html"

docker build --build-arg PAGES_DOMAIN=example.com -t "$image" ./nginx

docker run --rm --read-only --user 1000:1000 --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 \
    --tmpfs /var/cache/nginx:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 \
    "$image" nginx -t

rendered_nginx="$(docker run --rm --read-only --user 1000:1000 --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 \
    --tmpfs /var/cache/nginx:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 \
    "$image" nginx -T 2>&1)"
grep -Fq 'client_max_body_size 1m;' <<<"$rendered_nginx"
grep -Fq 'limit_req zone=webhook' <<<"$rendered_nginx"

docker run -d --name "$container" --read-only --user 1000:1000 --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --add-host deployer:127.0.0.1 \
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

printf '%032d\n' 0 > "$secret_dir/session"
printf '%032d\n' 0 > "$secret_dir/token-key"
printf 'oauth-client-secret\n' > "$secret_dir/oauth-client-secret"

deployer_compose="$(DOMAIN=example.com GITEA_API_URL=https://gitea.example.com \
    GITEA_PUBLIC_URL=https://gitea.example.com OAUTH_CLIENT_ID=pages-client \
    SESSION_SECRET_HOST_FILE="$secret_dir/session" \
    TOKEN_ENCRYPTION_KEY_HOST_FILE="$secret_dir/token-key" \
    OAUTH_CLIENT_SECRET_HOST_FILE="$secret_dir/oauth-client-secret" \
    docker compose config deployer)"
nginx_compose="$(DOMAIN=example.com GITEA_API_URL=https://gitea.example.com \
    GITEA_PUBLIC_URL=https://gitea.example.com OAUTH_CLIENT_ID=pages-client \
    SESSION_SECRET_HOST_FILE="$secret_dir/session" \
    TOKEN_ENCRYPTION_KEY_HOST_FILE="$secret_dir/token-key" \
    OAUTH_CLIENT_SECRET_HOST_FILE="$secret_dir/oauth-client-secret" \
    docker compose config nginx)"

! grep -Eq '^    ports:' <<<"$deployer_compose"
grep -Fq 'read_only: true' <<<"$deployer_compose"
grep -Fq 'ALL' <<<"$deployer_compose"
grep -Fq 'pids_limit:' <<<"$deployer_compose"
grep -Fq 'SESSION_SECRET_FILE: /run/secrets/gitea_pages_session_secret' <<<"$deployer_compose"
grep -Fq 'source: session_secret' <<<"$deployer_compose"
! grep -Fq '/dev/null' <<<"$deployer_compose"
grep -Fq 'published: "80"' <<<"$nginx_compose"
grep -Fq 'target: 8080' <<<"$nginx_compose"
grep -Fq 'read_only: true' <<<"$nginx_compose"
grep -Fq 'ALL' <<<"$nginx_compose"
