# Final Security Fix Report

Date: 2026-08-09 UTC

Branch: `security-remediation`

Commits: `72d4ad0` (`security: close final migration and redirect findings`) plus the containing cross-origin recovery follow-up

## Scope completed

- Replaced the end-only migration manifest with a version-2 encrypted write-ahead journal.
- Atomically rewrites the journal through a mode-0600 same-directory temporary file, then calls file `Sync`, checks `Close`, renames, opens and syncs the parent directory before every remote hook PATCH.
- Added a SQLite transaction commit marker keyed by a random migration ID. A later invocation compensates every journaled hook and retries when the database did not commit, or finalizes the manifest without another remote mutation when the database committed.
- Binds every compensating PATCH to that journal record's stored `GiteaAPIURL`, so changing the current migration configuration cannot redirect historical bearer or legacy hook credentials to another server.
- Preserved version-1 manifest restore compatibility and durable final-manifest writes.
- Made organization discovery errors abort migration. Known organization hook listing/rotation failures are skippable only with `--skip-failed-organizations`, and stderr prints the exact organization name.
- Applied the Task-1 HTTP allowlist to `OAUTH_REDIRECT_URL`, `WEBHOOK_PUBLIC_URL`, and the migration CLI: HTTP requires `APP_ENV=development` plus `localhost`, `127.0.0.1`, `::1`, or a single-label Docker DNS host.
- Added a shared no-redirect HTTP client for OAuth client-secret, OAuth bearer-token, hook-management, migration, restore, and canonical repository API requests.
- Added `http.followRedirects=false` before the Git clone subcommand.
- Added explicit GHCR images to both Compose files so the documented prebuilt flow does not require build contexts, while retaining source build blocks for `--build`.
- Removed both stale `auto_register.go` README entries.

## TDD evidence

The crash-recovery RED run failed to compile because migration checkpoint/state and durable recovery APIs did not exist. After implementation, `TestMigrationRecoversFromSIGKILLAtDurabilityBoundaries` passed at all three checkpoints:

- journal synced immediately before the first PATCH;
- remote PATCH applied before local credential persistence;
- SQLite transaction committed before final manifest rewrite.

The organization RED run showed `/api/v1/user/orgs` failures returned `nil` and silently completed for both skip modes. The GREEN run aborts both cases and retains the legacy database; a known `engineering` hook-list failure succeeds only with the explicit skip flag and prints `organization engineering was not migrated`.

The transport RED run demonstrated all original findings:

- production HTTP OAuth/webhook public URLs and disallowed development hosts were accepted;
- migration followed a 307 and sent `Authorization: Bearer ...` to the redirect target;
- OAuth token exchange followed a 307 and sent `client_secret` to the redirect target;
- the Git invocation failed the redirect-policy contract because `http.followRedirects=false` was absent.

The corresponding focused GREEN run passed every regression.

The final cross-origin recovery RED run crashed migration after server A's
remote PATCH, then retried with server B configured. The prior implementation
sent the compensation to B and failed later with `rotate user hook for alice:
EOF`. The GREEN run restores the legacy hook only on A; the test cancels on
that restore and verifies B receives zero requests and zero credentials.

## Fresh verification evidence

- Focused security regressions:
  - `/usr/local/go/bin/go test -count=1 -run 'TestMigration|TestLoadConfig|TestOAuth|TestExchangeCode|TestGitClone|TestGetRepoInfo|TestSecurityE2ERejectsRepositoryAPIRedirect' -v`
  - Result: PASS, including all three SIGKILL subtests.
- Full package:
  - `/usr/local/go/bin/go test -count=1 ./...`
  - Result: `ok gitea-pages-deployer`.
- Race detector:
  - `/usr/local/go/bin/go test -count=1 -race ./...`
  - Result: `ok gitea-pages-deployer`.
- Cross-origin recovery follow-up:
  - `/usr/local/go/bin/go test -count=1 -run 'TestMigrationRecoveryRestoresJournaledOriginWhenConfigurationChanges|TestMigrationRecoversFromSIGKILL|TestMigrationSIGKILLHelperProcess' -v`
  - Result: PASS; server A received the secure update plus legacy restore, and server B received no requests or credentials.
- Release gates:
  - `bash tests/compose_security_test.sh && bash tests/nginx_test.sh && bash tests/security_release_gate_test.sh`
  - Result: exit 0; Compose policy checks passed and the built Nginx configuration reported syntax successful.
- Release build/static analysis:
  - `CGO_ENABLED=0 /usr/local/go/bin/go build ./...`
  - `/usr/local/go/bin/go vet ./...`
  - Result: both exit 0.
- Diff hygiene:
  - `git diff --check`
  - Result: exit 0.

## Residual scope

No deferred low-severity findings were included. Completed rollback manifests intentionally remain until the operator's rollback window ends; rerunning migration with the same completed manifest path is rejected, while an in-progress manifest is recovered automatically.
