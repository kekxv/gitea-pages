# Final Security Findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the final branch-blocking crash-safety, migration completeness, transport-validation, and redirect-leak findings without expanding into deferred hardening.

**Architecture:** Replace the end-only rollback manifest with an encrypted, atomically rewritten write-ahead journal. Each legacy hook record is durably synced before its remote PATCH, while a migration ID committed inside the SQLite transaction lets a later process compensate an uncommitted crash or finalize a committed migration. Reuse one exact production/development URL policy and one no-redirect HTTP client policy across runtime, migration, OAuth, and bearer-token calls.

**Tech Stack:** Go 1.26, `net/http`, SQLite, AES-256-GCM, POSIX-style durable file replacement, Git CLI, Docker Compose.

## Global Constraints

- Work in the existing `security-remediation` worktree and preserve unrelated work.
- Use strict red/green TDD for every behavior change.
- The encrypted journal file and its parent directory must be synced before every migration hook PATCH.
- A SIGKILL must leave enough durable state either to restore every possibly changed hook or to finalize a database-committed migration.
- Organization discovery may never silently omit organizations.
- HTTP is allowed only with `APP_ENV=development` and host `localhost`, `127.0.0.1`, `::1`, or a single-label Docker DNS name.
- Secret-bearing HTTP requests and Git clones must reject redirects.
- Do not include deferred low-severity findings.

---

### Task 1: Durable encrypted migration journal and crash recovery

**Files:**
- Modify: `deployer/migrate_security.go`
- Modify: `deployer/migrate_security_test.go`

**Interfaces:**
- Produces: version-2 `securityMigrationManifest` containing `MigrationID`, `State`, and all pre-PATCH rollback records.
- Produces: `writeEncryptedMigrationManifest` as an atomic file-sync, close, rename, directory-sync operation.
- Produces: a SQLite migration commit marker keyed by the manifest migration ID.
- Consumes: existing `TokenCipher`, hook rollback records, and migration transaction.

- [ ] **Step 1: Add failing subprocess crash tests**

Add table-driven helper-process tests that SIGKILL migration immediately after journal sync, immediately after a remote PATCH, and immediately after SQLite commit. Assert that a second invocation compensates and completes the first two cases, finalizes the third without extra remote mutation, leaves an encrypted mode-0600 completed manifest, and commits the secure database exactly once.

- [ ] **Step 2: Run the crash tests and verify RED**

Run: `cd deployer && go test -run 'TestMigrationRecoversFromSIGKILL|TestMigrationCrashHelperProcess' -v`

Expected: FAIL because the manifest is created only after all PATCH requests and there is no committed migration identity or recovery path.

- [ ] **Step 3: Implement the minimal durable journal**

Create an initial encrypted journal before migration work. Before each remote hook PATCH, append the exact legacy rollback record and atomically rewrite it through a same-directory temporary file: chmod 0600, write all ciphertext, `Sync`, `Close`, `Rename`, then open and `Sync` the parent directory. Store the migration ID in a table created and populated inside the migration transaction. On startup, decrypt an existing journal: compensate and durably remove it when its ID is not committed, or rewrite it as completed and return when its ID is committed.

- [ ] **Step 4: Verify GREEN and regression behavior**

Run: `cd deployer && go test -run 'TestMigration' -v`

Expected: PASS, including ambiguous network rollback and encrypted-manifest tests.

---

### Task 2: Fail closed on organization discovery and listing

**Files:**
- Modify: `deployer/migrate_security.go`
- Modify: `deployer/migrate_security_test.go`

**Interfaces:**
- Changes: `discoverMigrationOrganizations` returns `(map[string][]string, error)`.
- Preserves: `--skip-failed-organizations` only for a known organization whose hook listing/rotation failed, with exact organization-name output.

- [ ] **Step 1: Add failing discovery/listing tests**

Add tests where `/api/v1/user/orgs` fails and assert migration aborts even with the skip flag because an exact omitted organization cannot be identified. Capture stderr for a known organization hook-list failure with the skip flag and assert the exact organization name is printed.

- [ ] **Step 2: Run and verify RED**

Run: `cd deployer && go test -run 'TestMigration.*Organization' -v`

Expected: FAIL because discovery errors are currently ignored and the existing skip test does not verify exact-name output.

- [ ] **Step 3: Propagate discovery errors and preserve exact-name skip behavior**

Return the username-scoped organization discovery error to `RunSecurityMigration`. Continue to route known organization hook-list/rotation errors through the existing explicit skip branch and exact-name stderr message.

- [ ] **Step 4: Verify GREEN**

Run: `cd deployer && go test -run 'TestMigration.*Organization' -v`

Expected: PASS.

---

### Task 3: Enforce the URL and no-redirect policies

**Files:**
- Modify: `deployer/config_test.go`
- Modify: `deployer/main.go`
- Modify: `deployer/migrate_security_test.go`
- Modify: `deployer/migrate_security.go`
- Modify: `deployer/oauth_security_test.go`
- Modify: `deployer/oauth.go`
- Modify: `deployer/gitea.go`
- Modify: `deployer/git_test.go`
- Modify: `deployer/git.go`

**Interfaces:**
- Produces: shared URL validation for Gitea, OAuth redirect, and webhook public URLs using the exact development allowlist.
- Produces: shared secret-bearing `http.Client` constructor/copy that rejects all redirects.
- Changes: Git clone arguments include `-c http.followRedirects=false` before `clone`.

- [ ] **Step 1: Add failing URL and redirect tests**

Add production rejection and exact development-allowlist cases for `OAUTH_REDIRECT_URL` and `WEBHOOK_PUBLIC_URL`; add migration CLI validation cases for `WEBHOOK_PUBLIC_URL`; add redirect-capture tests proving OAuth client secrets and bearer tokens do not reach a redirect target; and add a Git invocation test that fails unless initial redirects are disabled before `clone`.

- [ ] **Step 2: Run and verify RED**

Run: `cd deployer && go test -run 'TestLoadConfig.*(Redirect|Webhook)|TestMigration.*HTTP|TestOAuth.*Redirect|TestGitClone.*Redirect' -v`

Expected: FAIL because public URLs accept production HTTP, migration uses parse-only validation, OAuth/migration clients follow redirects, and Git does not set `http.followRedirects=false`.

- [ ] **Step 3: Implement minimal shared policies**

Validate every supplied public URL with the same scheme/environment/host rule. Pass `APP_ENV` into migration configuration from the CLI. Clone injected HTTP clients and override `CheckRedirect`; use the same rejecting client for OAuth exchange, refresh, user/org lookup, hook mutation/rollback, migration, and canonical repository API requests. Add the Git config before the clone subcommand.

- [ ] **Step 4: Verify GREEN**

Run: `cd deployer && go test -run 'TestLoadConfig|TestMigration|TestOAuth|TestGitClone|TestGetRepoInfo' -v`

Expected: PASS.

---

### Task 4: Correct prebuilt documentation and stale source listing

**Files:**
- Modify: `docker-compose.yml`
- Modify: `docker-compose.example.yml`
- Modify: `README.md`

**Interfaces:**
- Produces: Compose services with explicit GHCR images while retaining source build contexts for `--build`.
- Removes: stale `auto_register.go` README entries.

- [ ] **Step 1: Add explicit image references to both Compose files**

Set `image: ghcr.io/kekxv/gitea-pages/nginx:latest` and `image: ghcr.io/kekxv/gitea-pages/deployer:latest` beside the existing build blocks so downloaded Compose files can pull prebuilt images and source checkouts can still build.

- [ ] **Step 2: Correct both README languages**

Keep the prebuilt `docker compose pull && docker compose up -d` path tied to the image-backed Compose file, preserve the source `--build` path, and remove both stale `auto_register.go` tree entries.

- [ ] **Step 3: Validate Compose rendering**

Run: `bash tests/compose_security_test.sh`

Expected: PASS.

---

### Task 5: Full verification, report, and commit

**Files:**
- Create: `task-final-security-fix-report.md`

**Interfaces:**
- Produces: a concise evidence report with red/green tests, focused/full/race/release gate output, residual limitations, and commit ID.

- [ ] **Step 1: Format and inspect the diff**

Run: `cd deployer && gofmt -w migrate_security.go migrate_security_test.go main.go config_test.go git.go git_test.go gitea.go oauth.go oauth_security_test.go`

Run: `git diff --check && git diff --stat && git status --short`

- [ ] **Step 2: Run focused and full gates**

Run: `cd deployer && go test -count=1 -run 'TestMigration|TestLoadConfig|TestOAuth|TestGitClone|TestGetRepoInfo' -v`

Run: `cd deployer && go test -count=1 ./...`

- [ ] **Step 3: Run race and release gates**

Run: `cd deployer && go test -count=1 -race ./...`

Run: `bash tests/compose_security_test.sh && bash tests/nginx_test.sh && bash tests/security_release_gate_test.sh`

- [ ] **Step 4: Write the evidence report and commit**

Record exact commands and outcomes in `task-final-security-fix-report.md`, then commit only this cohesive security-fix wave with message `security: close final migration and redirect findings`.
