# Task 12 — Security CI, operator documentation, and release gates

## Base

`6b567fc` (`test: cover cross-tenant and destructive security regressions`)

## Delivered

- Added `.github/workflows/security.yml`, a least-privilege security release
  gate for pull requests, `main`, and manual dispatch. Third-party actions are
  immutable commit pins; Go, `govulncheck`, and Trivy versions are explicit.
- The workflow runs module-local (`deployer/`) race tests with coverage and
  `govulncheck`, validates Compose, executes containment and Nginx runtime
  tests, builds SHA-tagged release candidates, and blocks on Trivy high/critical
  configuration findings or critical image findings.
- Added `docs/security.md` covering the scoped hook trust model, untrusted
  static-content model, Docker/SSH containment, secret rotation, token
  compromise, forged-hook, disk-exhaustion, offline migration, rollback, and
  release evidence.
- Updated README and AI.md to remove retired shared-token/administrator-scope
  instructions, document the file-mounted-secret and Nginx-only-public-port
  topology, and require offline migration before the hardened runtime starts.
- Preserved the approved organization-hook architecture: automatic organization
  registration remains enabled by default through the approved administrator
  token pool (`ENABLE_ORGANIZATION_HOOKS=true`).
- Removed the obsolete top-level `tests/integration_test.go`: it was a
  non-module test harness that referenced pre-migration APIs. The active Go
  regression suite is module-resident in `deployer/`; shell policy tests remain
  under `tests/`.
- Added `tests/security_release_gate_test.sh` to prevent stale workflow,
  documentation, action-pinning, and historical-test-path regressions.
- Updated the digest-pinned Nginx base to `1.29-alpine` after the former image
  had critical OpenSSL findings in the current Trivy database.

## TDD and verification evidence

1. The new workflow/documentation policy test initially failed because
   `.github/workflows/security.yml` did not exist; it passed after the gate and
   documentation were added.
2. The historical-test assertion initially failed while
   `tests/integration_test.go` existed; it passed after removal.
3. The Nginx pin assertion was changed to the remediated base and failed
   against the prior image before the Dockerfile update.
4. Verified locally:

```text
bash tests/security_release_gate_test.sh                         # PASS
bash -n tests/security_release_gate_test.sh tests/compose_security_test.sh tests/nginx_test.sh  # PASS
docker compose --env-file .env.example config --quiet             # PASS
bash tests/compose_security_test.sh                               # PASS
bash tests/nginx_test.sh                                          # PASS
cd deployer && go vet ./... && go test -race -coverprofile=coverage.out ./...  # PASS (66.5% coverage)
cd deployer && govulncheck ./...                                  # PASS with Go 1.26.5 (no vulnerabilities)
trivy config --exit-code 1 --severity HIGH,CRITICAL .             # PASS
trivy image --exit-code 1 --severity CRITICAL gitea-pages-deployer:task12  # PASS
trivy image --exit-code 1 --severity CRITICAL gitea-pages-nginx:task12     # PASS
git diff --check                                                  # PASS
```

The brief's historical `cd tests && go test -race ./...` command was not
carried forward: `tests/` was not a Go module and the removed harness used the
pre-security API. CI now invokes the actual module location (`deployer/`).

## Round 1 — quickstart and public-route remediation

- Removed the unsafe runnable quickstart Compose stack, generated environment
  template, test script, and cleanup script. They exposed Deployer on a host
  port and retained shared credentials and plaintext OAuth client secrets.
- Replaced the quickstart with a bilingual migration-safe guide to the
  repository-root hardened topology: Nginx-only ingress, file-mounted secrets,
  public `pages.<DOMAIN>` OAuth/webhook routes, automatic organization hooks,
  and the required offline migration for legacy deployments.
- Updated both README authorization links and the root environment example so
  neither sends users to a public Deployer `:8080` endpoint.
- Expanded the release-contract test to scan README, AI guidance, security
  documentation, the root environment example, and every example for retired
  shared-token/global-secret variables, plaintext OAuth secret assignments,
  administrator scopes, and public Deployer OAuth/webhook routes.

### Round 1 TDD evidence

The expanded release-contract test first failed and listed the stale root
environment callback plus all unsafe quickstart files. It passes after their
removal/replacement and the documentation updates.
