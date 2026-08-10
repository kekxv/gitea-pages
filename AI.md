# Gitea Pages — current architecture contract

Use this document as the source of truth when changing Gitea Pages. It
supersedes the early prototype design.

## Deployment topology

- Nginx is the only service with a published host port. It terminates the
  public Pages control route `<DOMAIN>` and user subdomains under it.
- Deployer has no published host port. Nginx forwards its OAuth and webhook
  routes to Deployer on the internal `pages_backend` network.
- Deployer can reach Gitea through its dedicated egress network, but has no
  Docker socket, no SSH key, no privileged mode, no Linux capabilities, and a
  read-only root filesystem.
- Nginx mounts Pages data read-only. Deployer alone writes the Pages volume and
  publishes a new site atomically after validation.
- Both containers run as the configured non-root UID/GID, use restrictive
  tmpfs mounts, and have process, CPU, and memory limits.

## Authentication and authority

- A hook key identifies one registered Gitea hook. It does not authenticate a
  delivery by itself.
- Each hook has its own HMAC secret, which authenticates exactly its personal
  or organization scope. Hook credentials must never be shared across scopes.
- Treat every webhook payload as untrusted input. It cannot select an OAuth
  token or establish repository identity.
- Resolve the hook scope and repository through the Gitea API. Canonical Gitea
  metadata—not the payload's owner, repository ID, clone URL, or visibility
  field—is authoritative.
- Treat checked-out repository content as hostile static data: reject unsafe
  site targets and clone transports, prevent symlinks, strip Git metadata and
  executable permissions, apply size/time/concurrency limits, and publish only
  after the complete replacement is ready.

## OAuth and organization hooks

- OAuth grants are encrypted at rest with `TOKEN_ENCRYPTION_KEY_FILE`; session
  and OAuth client secrets are file-mounted Compose secrets, never ordinary
  environment values.
- Personal and organization hook registration is automatic. The approved
  administrator token pool supplies organization authorization when needed.
- `ENABLE_ORGANIZATION_HOOKS=true` is the approved default. Set it to `false`
  only for an installation intentionally restricted to personal repositories.
- Do not add global webhook secrets, payload-selected OAuth tokens, shared
  administrator access tokens, or any fallback HTTP authentication path.

## Offline migration and rollback

Existing installations using the historical shared webhook secret must run the
**offline migration** before starting the hardened runtime:

```bash
deployer migrate-security \
  --backup /secure/backups/tokens.db.before-security-migration \
  --manifest /secure/backups/legacy-hooks.manifest
```

Stop Deployer but leave Nginx serving the last published static content. The
migration requires `TOKEN_ENCRYPTION_KEY_FILE`, `LEGACY_WEBHOOK_SECRET_FILE`,
`GITEA_API_URL`, and `WEBHOOK_PUBLIC_URL`; it encrypts legacy OAuth rows and
rotates every reachable hook to its scoped credential. The backup must already
exist and have mode `0600`; the encrypted manifest also has mode `0600` and is
retained only for the rollback window.

To roll back, stop the new Deployer, restore external hooks using the manifest,
restore the v1 database backup, and start the recorded old image digest:

```bash
deployer restore-legacy-hooks \
  --manifest /secure/backups/legacy-hooks.manifest
```

After the rollback window expires, remove the legacy secret file from the host.
The normal HTTP handler must never accept that old shared secret.

## Release requirements

The security workflow is mandatory on pull requests and the main branch. It
runs module-local Go race tests and coverage from `deployer/`, `govulncheck`,
Compose topology and containment checks, the non-root Nginx test, and Trivy
configuration/image scans. Do not invoke the historical top-level `tests/`
directory as a Go module; its executable tests are shell policy checks, while
the Go module and end-to-end regression suite live in `deployer/`.

Before a production migration, record image digests, `0600` backup location,
hook counts before and after migration, successful delivery IDs, and rollback
window expiry. Keep forensic logs for suspected token compromise, forged-hook
attempts, deployment timeouts, or disk exhaustion; preserve existing sites by
stopping Deployer before any cleanup.
