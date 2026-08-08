# Security Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate plaintext OAuth tokens and shared webhook secrets offline into encrypted tokens and per-hook credentials with a recoverable external rollback path.

**Architecture:** The migration opens `tokens.db` directly under an exclusive SQLite transaction, validates an existing protected backup, copies v1 rows into the encrypted v2 schema, rotates Gitea hooks, and commits only after mandatory personal hook changes. An AES-GCM encrypted manifest records non-secret old hook metadata and encrypted API credentials so a separate offline command can restore Gitea before the database backup is restored.

**Tech Stack:** Go 1.26, modernc SQLite, AES-256-GCM, Gitea REST API, Go `flag`.

## Global Constraints

- This is an offline CLI migration; HTTP handler behavior is not changed here.
- The supplied database backup must already exist and be mode `0600`.
- Plaintext `user_tokens` rows are removed only within the final database transaction.
- A user hook failure aborts and rolls back the database; an organization failure can proceed only with `--skip-failed-organizations` and names the organization.
- The database and manifest never retain plaintext access, refresh, or legacy webhook secrets.
- Existing organization authorizer identities are preferred; eligible OAuth users are fallback candidates.

---

### Task 1: Specify rollback and manifest behavior

**Files:**
- Create: `deployer/migrate_security_test.go`

**Interfaces:**
- Produces `RunSecurityMigration(context.Context, SecurityMigrationConfig) error` and `RestoreLegacyHooks(context.Context, LegacyHookRestoreConfig) error`.

- [ ] **Step 1: Write the failing test**

```go
func TestMigrationRollsBackDatabaseWhenUserHookRotationFails(t *testing.T) {
	config := seededMigrationConfig(t, failingSecondUserHookServer(t))
	if err := RunSecurityMigration(context.Background(), config); err == nil {
		t.Fatal("expected user hook migration failure")
	}
	assertLegacyTokenRowExists(t, config.DatabasePath, "alice")
	assertNoHookCredentialRows(t, config.DatabasePath)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker run --rm -v "$PWD/deployer:/src" -w /src golang:1.26-alpine go test -run TestMigration -v`

Expected: FAIL because `RunSecurityMigration` is undefined.

- [ ] **Step 3: Write minimal implementation**

Create the configuration and direct-SQLite transaction skeleton.

- [ ] **Step 4: Run test to verify it passes**

Run: `docker run --rm -v "$PWD/deployer:/src" -w /src golang:1.26-alpine go test -run TestMigrationRollsBackDatabaseWhenUserHookRotationFails -v`

Expected: PASS.

### Task 2: Encrypt rows and rotate hooks

**Files:**
- Create: `deployer/migrate_security.go`
- Modify: `deployer/storage.go`
- Test: `deployer/migrate_security_test.go`

**Interfaces:**
- Consumes legacy `user_tokens` and `HookCredential` / `HookPrincipal`.
- Produces `user_tokens_v2`, `hook_credentials`, organization authorizers, and a mode-0600 encrypted manifest.

- [ ] **Step 1: Write the failing test**

```go
func TestMigrationManifestContainsNoPlaintextSecrets(t *testing.T) {
	config := seededMigrationConfig(t, successfulHookServer(t))
	if err := RunSecurityMigration(context.Background(), config); err != nil { t.Fatal(err) }
	manifest, err := os.ReadFile(config.ManifestPath)
	if err != nil { t.Fatal(err) }
	if bytes.Contains(manifest, []byte("plain-access-token")) || bytes.Contains(manifest, []byte("legacy-webhook-secret")) {
		t.Fatal("rollback manifest contains plaintext secret")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker run --rm -v "$PWD/deployer:/src" -w /src golang:1.26-alpine go test -run TestMigrationManifestContainsNoPlaintextSecrets -v`

Expected: FAIL because no manifest exists.

- [ ] **Step 3: Write minimal implementation**

Factor schema creation into a transaction helper, AES-GCM encrypt token fields, create one credential per legacy user/org hook, retain authorizers, and serialize only restoration metadata plus encrypted API credentials.

- [ ] **Step 4: Run test to verify it passes**

Run: `docker run --rm -v "$PWD/deployer:/src" -w /src golang:1.26-alpine go test -run TestMigration -v`

Expected: PASS.

### Task 3: Restore command and operating procedure

**Files:**
- Modify: `deployer/main.go`
- Create: `deployer/migrate_security.go`
- Modify: `README.md`
- Test: `deployer/migrate_security_test.go`

**Interfaces:**
- Produces `deployer migrate-security --backup PATH --manifest PATH [--skip-failed-organizations]`.
- Produces `deployer restore-legacy-hooks --manifest PATH` using `LEGACY_WEBHOOK_SECRET_FILE`.

- [ ] **Step 1: Write the failing test**

```go
func TestRestoreLegacyHooksUsesEncryptedManifest(t *testing.T) {
	config := migratedConfig(t, successfulHookServer(t))
	if err := RestoreLegacyHooks(context.Background(), LegacyHookRestoreConfig{ManifestPath: config.ManifestPath, TokenEncryptionKey: config.TokenEncryptionKey, LegacyWebhookSecret: []byte("legacy-webhook-secret")}); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker run --rm -v "$PWD/deployer:/src" -w /src golang:1.26-alpine go test -run TestRestoreLegacyHooks -v`

Expected: FAIL because `RestoreLegacyHooks` is undefined.

- [ ] **Step 3: Write minimal implementation**

Parse flags before server startup, validate secret-file inputs, decrypt the manifest, PATCH every recorded hook back using the old secret file, aggregate failures, and document the seven required production gates.

- [ ] **Step 4: Run test to verify it passes**

Run: `docker run --rm -v "$PWD/deployer:/src" -w /src golang:1.26-alpine go test -run 'TestMigration|TestRestoreLegacyHooks' -v`

Expected: PASS.

### Task 4: Verify and commit

**Files:**
- Modify: `deployer/migrate_security.go`, `deployer/migrate_security_test.go`, `deployer/main.go`, `deployer/storage.go`, `README.md`

- [ ] **Step 1: Run focused tests**

Run: `docker run --rm -v "$PWD/deployer:/src" -w /src golang:1.26-alpine go test -run 'TestMigration|TestRestoreLegacyHooks' -v`

- [ ] **Step 2: Run full and race tests**

Run: `docker run --rm -v "$PWD/deployer:/src" -w /src golang:1.26-alpine go test ./... && docker run --rm -v "$PWD/deployer:/src" -w /src golang:1.26-alpine go test -race ./...`

- [ ] **Step 3: Commit**

```bash
git add deployer/migrate_security.go deployer/migrate_security_test.go deployer/main.go deployer/storage.go README.md docs/superpowers/plans/2026-08-08-security-migration.md .superpowers/sdd/2026-08-08-security-remediation/task-10-report.md
git commit -m "security: add transactional credential migration"
```
