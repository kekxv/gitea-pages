# Task 8 Report: Harden Nginx Routing and Compose Topology

## Status

Completed from base `9bbb98d` as `security: fix non-root nginx and bind the pages domain`.

## Delivered

- Nginx now runs read-only as UID/GID 1000, stores its PID in `/tmp`, logs to
  standard streams, and keeps all temporary/cache directories in
  `/var/cache/nginx`.
- The image validates `PAGES_DOMAIN` at build time, escapes it into the final
  configuration, and removes the template from the final image. User sites
  match only `username.pages.<configured-domain>`; unknown hosts return 421.
- The separate `pages.<configured-domain>` virtual host explicitly proxies the
  control plane to Deployer. It is not a broad `pages.*` wildcard.
- Compose publishes only Nginx on host port 80 to container port 8080.
  Deployer has no published ports, is reachable on an internal backend only,
  and retains a separate egress network for Gitea API and clone traffic.
- Both runtime services use UID 1000, read-only roots, `no-new-privileges`, all
  capabilities dropped, PID/CPU/memory limits, and only the required writable
  data volumes and hardened tmpfs paths.
- Required session, token-encryption, and OAuth client secrets are Compose
  secrets with no `/dev/null` or empty-value fallback. The example environment
  now names required host secret files without embedding secret values.

## TDD evidence

`tests/nginx_test.sh` was added before changing Nginx or Compose. Against the
Task 8 base, its initial smoke command failed as expected because Nginx tried
to create `/var/run/nginx/nginx.pid` on a read-only filesystem. After the
read-only Nginx changes, the same test advanced to its Compose assertions and
failed as expected because Deployer still published port 8080 and lacked the
required sandbox limits.

## Verification

Fresh verification executed from the repository root:

```sh
bash tests/nginx_test.sh
if docker build --build-arg PAGES_DOMAIN='example.com;bad' -t gitea-pages-nginx:invalid ./nginx; then exit 1; fi
(cd deployer && /usr/local/go/bin/go test ./...)
git diff --check
```

The smoke test builds the image, runs `nginx -t` under a read-only UID 1000
container with all capabilities dropped, then verifies valid Alice routing,
attacker-domain rejection, hidden-path protection, and rendered Compose
topology. The invalid-domain build fails as required; the surrounding shell
assertion confirms that failure. Whitespace validation is clean.
