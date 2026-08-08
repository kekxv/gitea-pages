# Task 10 — Transactional Security Migration Report

## Delivered

- Added offline `deployer migrate-security --backup PATH --manifest PATH [--skip-failed-organizations]`.
- Added offline `deployer restore-legacy-hooks --manifest PATH`.
- Migration validates an existing `0600` regular-file database backup, obtains an exclusive SQLite transaction, encrypts v1 access/refresh token rows into `user_tokens_v2`, writes per-hook credentials, and removes `user_tokens` only at the end of the transaction.
- User hook failure rolls back the local database and reverses already-rotated Gitea hooks in reverse order.
- Organization migration prefers retained `organization_hook_authorizers`; it then uses OAuth users that can enumerate the organization. An organization failure is accepted only with `--skip-failed-organizations`, which writes the exact organization name and manual reauthorization requirement to stderr.
- The rollback manifest is AES-GCM encrypted, created with `0600`, and never stores the legacy webhook secret. It contains the hook ID, scope, former URL/header/configuration metadata, and API credentials only inside the encrypted payload.
- Restore decrypts the manifest, reads the old webhook secret from `LEGACY_WEBHOOK_SECRET_FILE`, PATCHes every recorded hook back to its old URL, secret, and authorization header, and returns a non-zero CLI status if any restore fails.
- Shared storage schema creation is now reusable by the offline transaction, avoiding a second schema definition.
- README documents the required seven-gate production migration and rollback sequence.

## Scope boundary

No HTTP webhook handler was changed. Per the assigned sequencing, final removal of the legacy HTTP signature fallback must be applied by the handler-integration task after this migration tooling is available. Operators must remove `LEGACY_WEBHOOK_SECRET_FILE` after the rollback window; the documented normal runtime then has no legacy secret configured.

## Test coverage

- User hook API failure preserves the legacy database and leaves no committed hook-credential schema.
- Successful migration encrypts token data, removes v1 rows, creates personal and organization credentials, and produces a secret-free raw manifest.
- Backup permission validation rejects anything other than `0600`.
- Legacy tables without optional refresh/type/timestamp columns still migrate access tokens correctly.
- Explicit organization skip commits the personal hook only.
- Restore is verified to PATCH both personal and organization hooks with the prior authorization header and legacy secret.

## Verification evidence

Executed from `deployer/` using the cached Go 1.26 toolchain:

```text
/usr/local/go/bin/go test -run 'TestMigration|TestRestoreLegacyHooks' -v  # PASS (6 tests)
/usr/local/go/bin/go test ./...                                            # PASS
/usr/local/go/bin/go test -race ./...                                      # PASS
git diff --check                                                            # PASS
```
