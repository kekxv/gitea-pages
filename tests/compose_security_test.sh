#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
audit_dir=$(mktemp -d)
trap 'rm -rf "$audit_dir"' EXIT

# There is one authoritative Compose configuration. Keeping a second copied
# example causes security defaults to drift between the two files.
test ! -e "$repo_root/docker-compose.example.yml"

printf '%s\n' 'session-secret-material-at-least-thirty-two-bytes' > "$audit_dir/session_secret"
printf '%032d' 0 | tr '0' 'k' > "$audit_dir/token_encryption_key"
printf '%s\n' 'oauth-client-secret-material' > "$audit_dir/oauth_client_secret"
mkdir -p "$audit_dir/pages"

audit_env="$audit_dir/.env"
cp "$repo_root/.env.example" "$audit_env"
cat >> "$audit_env" <<EOF
PAGES_SESSION_SECRET_HOST_FILE=$audit_dir/session_secret
PAGES_TOKEN_ENCRYPTION_KEY_HOST_FILE=$audit_dir/token_encryption_key
PAGES_OAUTH_CLIENT_SECRET_HOST_FILE=$audit_dir/oauth_client_secret
PAGES_DATA_DIR=$audit_dir/pages
PAGES_HTTP_PORT=18080
PAGES_UID=1234
PAGES_GID=5678
EOF

audit_config="$audit_dir/compose.json"
(
  cd "$repo_root"
  docker compose --env-file "$audit_env" config --format json > "$audit_config"
)

AUDIT_CONFIG="$audit_config" python3 - <<'PY'
import json
import os

with open(os.environ["AUDIT_CONFIG"], encoding="utf-8") as audit_file:
    config = json.load(audit_file)

services = config["services"]
nginx = services["nginx"]
deployer = services["deployer"]

def require(condition, message):
    if not condition:
        raise SystemExit(message)

runtime_uid = "1234"
runtime_gid = "5678"

def assert_least_privilege(name, service):
    require(service.get("user") == f"{runtime_uid}:{runtime_gid}", f"{name} must run as the configured non-root user")
    require(service.get("read_only") is True, f"{name} must have a read-only root filesystem")
    require(service.get("cap_drop") == ["ALL"], f"{name} must drop every Linux capability")
    require("no-new-privileges:true" in service.get("security_opt", []), f"{name} must forbid privilege escalation")
    require(service.get("pids_limit") == 128, f"{name} must limit processes to 128")
    require(service.get("cpus"), f"{name} must set a CPU limit")
    require(service.get("mem_limit"), f"{name} must set a memory limit")

assert_least_privilege("nginx", nginx)
assert_least_privilege("deployer", deployer)

require(not deployer.get("ports"), "deployer must not publish a host port")
require(deployer.get("expose") == ["8080"], "deployer must only expose its internal webhook port")

nginx_networks = set(nginx.get("networks", []))
deployer_networks = set(deployer.get("networks", []))
require("pages_frontend" in nginx_networks, "nginx must attach to a public frontend network")
require("pages_frontend" not in deployer_networks, "deployer must not attach to the public frontend network")
require(config["networks"]["pages_frontend"].get("internal") is not True, "the nginx frontend network must accept host ingress")
require(config["networks"]["pages_backend"].get("internal") is True, "the deployer backend network must remain internal")

secrets = {secret["target"]: secret for secret in deployer.get("secrets", [])}
for target in (
    "gitea_pages_session_secret",
    "gitea_pages_token_encryption_key",
    "gitea_pages_oauth_client_secret",
):
    secret = secrets.get(target)
    require(secret is not None, f"deployer must mount {target} as a Compose secret")
    require(secret.get("uid") == runtime_uid and secret.get("gid") == runtime_gid, f"{target} must be owned by the runtime user")
    require(secret.get("mode") == "0400", f"{target} must be read-only to the runtime user")

require("WEBHOOK_SECRET" not in deployer.get("environment", {}), "deployer must not receive a webhook secret environment value")
require("GITEA_SSH_KEY_PATH" not in deployer.get("environment", {}), "deployer must not receive an SSH key path")
require(any(mount.startswith("/tmp:") and f"uid={runtime_uid}" in mount and f"gid={runtime_gid}" in mount and "noexec" in mount for mount in deployer.get("tmpfs", [])), "deployer must have a noexec /tmp tmpfs owned by the runtime user")
require(any(mount.startswith("/tmp:") and "size=256m" in mount for mount in deployer.get("tmpfs", [])), "deployer /tmp must have a 256 MiB size limit")
require(any(mount.startswith("/tmp:") and f"uid={runtime_uid}" in mount and f"gid={runtime_gid}" in mount and "noexec" in mount for mount in nginx.get("tmpfs", [])), "nginx must have a noexec /tmp tmpfs owned by the runtime user")
require(any(mount.startswith("/var/cache/nginx:") and f"uid={runtime_uid}" in mount and f"gid={runtime_gid}" in mount and "noexec" in mount for mount in nginx.get("tmpfs", [])), "nginx must have a noexec cache tmpfs owned by the runtime user")
PY
