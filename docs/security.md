# Security model and release operations

This document is the operator contract for the hardened Gitea Pages release.
Treat a failure of any gate in this document as a release blocker.

## Trust model

- A **hook key is an identifier** for exactly one registered Gitea hook. It is
  not a bearer credential and is never sufficient to authorize a delivery.
- A **hook secret authenticates one scope** (a personal account or one named
  organization) by HMAC verification of the exact request body. Secrets are
  independently generated and are never shared between scopes.
- **OAuth tokens never come from payload identity.** A webhook body cannot
  select an OAuth grant or its permissions. The saved, encrypted grant belongs
  to the registered hook scope.
- **Gitea API metadata is canonical.** The Deployer resolves the hook scope and
  repository through Gitea before it accepts an owner, repository ID, clone URL,
  or visibility claim. Payload fields are assertions to verify, not authority.
- **Static repository content is untrusted.** It is copied as data only:
  symlinks, unsafe paths, oversized publications, executable permissions, and
  Git metadata are rejected or stripped before publication. Nginx also blocks
  hidden paths and serves the publication volume read-only.
- The Deployer has **no Docker socket or SSH key**. It has no published host
  port, runs unprivileged with a read-only root filesystem and no Linux
  capabilities, and can reach Gitea only through its egress network. Nginx is
  the sole service that publishes a host port; it reaches Deployer only on the
  private backend network.

Organization hooks are enabled by default through the approved administrator
token pool. Set `ENABLE_ORGANIZATION_HOOKS=true` to preserve that automatic
registration behavior; operators may explicitly disable it for installations
that choose to serve personal repositories only.

## Secret rotation

Rotate one scope at a time. Create a new per-hook key/secret pair, update the
matching Gitea hook, persist the new encrypted credential, then send a signed
delivery and confirm it reaches the intended site. Retire the old credential
only after that delivery succeeds. Rotate OAuth client, session, and encryption
secrets through a planned restart; preserve the existing encryption key until
every token and rollback manifest that needs it has expired or been migrated.
Never put secrets in Compose environment variables, repository files, image
layers, logs, or command-line arguments.

## Incident response

### Suspected token compromise

1. Disable the affected Gitea OAuth grant and hook immediately; do not infer
   the affected account from a webhook payload.
2. Revoke the OAuth token in Gitea, remove the encrypted token row, and rotate
   that hook's key and secret.
3. Inspect Gitea audit logs, Deployer logs, hook deliveries, and publication
   timestamps for the affected scope. Preserve the evidence and deploy a known
   good static revision if publication changed.
4. Require the owner to complete OAuth again before registering a replacement
   hook. Rotate the OAuth client secret as well if client compromise is
   possible.

### Forged-hook response

1. Preserve the request metadata and response status; do not log its body or
   signature value.
2. Confirm that the hook key, HMAC secret, and canonical Gitea metadata agree.
   A missing or mismatched value is an authentication event, not a deploy retry.
3. Rate-limit or block the source at the external proxy if the event repeats.
   Rotate only the implicated scope's hook credential after preserving evidence.
4. Check that no Git invocation or published-file change occurred; restore the
   last known good publication if any integrity check fails.

### Disk-exhaustion response

1. Stop new deployments by stopping Deployer; keep Nginx running so existing
   static sites remain available.
2. Measure the Pages volume and Deployer data volume, preserve logs, and remove
   only confirmed temporary clone directories or obsolete releases according to
   retention policy. Do not delete live site roots as a first response.
3. Increase capacity or lower `MAX_SITE_SIZE_MB`, `MAX_REPOSITORY_SIZE_MB`, and
   concurrency as needed, then verify free space and an atomic test deployment
   before restarting Deployer.

## Offline migration and rollback

Existing installations that used a shared webhook secret must complete the
offline migration before starting the hardened image. The normal HTTP server
does not accept the legacy shared secret. Back up the database to an existing
`0600` file, stop only Deployer, and retain the old image digest and encrypted
rollback manifest for the approved rollback window:

```bash
deployer migrate-security \
  --backup /secure/backups/tokens.db.before-security-migration \
  --manifest /secure/backups/legacy-hooks.manifest
```

The migration reads `TOKEN_ENCRYPTION_KEY_FILE`,
`LEGACY_WEBHOOK_SECRET_FILE`, `GITEA_API_URL`, and `WEBHOOK_PUBLIC_URL` only
while it runs. Nginx may continue to serve existing content. Verify encrypted
rows, per-hook counts, and one personal plus (when enabled) one organization
delivery before starting the new Deployer. Delete the legacy secret from the
host only after the rollback window expires.

## Rollback procedure

1. Stop the new Deployer and preserve its logs, image digest, database, and the
   migration manifest. Leave Nginx serving the last known good static content.
2. Run `deployer restore-legacy-hooks --manifest
   /secure/backups/legacy-hooks.manifest` with the same encryption key and
   `LEGACY_WEBHOOK_SECRET_FILE`. The command must complete every recorded
   Gitea hook restoration.
3. Restore the v1 database backup, start the pinned old Deployer image, and
   send a signed test delivery for each restored scope.
4. Record the restored hook count, backup location, old and new image digests,
   the incident decision, and the rollback-window expiry in the release ticket.

## Release evidence

Before release, run the Security release gate workflow and retain its logs.
For the production change, record image digests, database backup locations,
hook counts before and after migration, successful delivery IDs, and the
rollback-window expiry. Do not run `git clean -fdx` as part of this process;
`git clean -ndx` is preview-only.
