# Webhook Handler Integration Report

## Scope

Integrated the post-migration webhook runtime with the previously delivered
per-hook authentication, canonical repository verifier, `SiteTarget`, and
bounded deployment service. This removes the runtime shared-secret webhook
path; legacy webhook secrets remain available only to the offline migration
and rollback commands.

The handler now performs this sequence for every POST delivery:

1. `AuthenticateWebhook(r.Context(), r, d.hookStore)`
2. `DecodeWebhook(authenticated.Body, r.Header.Get("X-Gitea-Event"))`
3. `d.repositoryVerifier.Verify(r.Context(), authenticated.Principal, payload.Repository)`
4. `NewSiteTarget(d.config.PagesDir, repo.Owner, repo.Name, d.config.Domain)`
5. `d.deployments.Deploy` or `d.deployments.Remove`

`main` constructs the encrypted `TokenStore` first, then creates the
repository verifier and deployment service, and only then constructs the
webhook handler. No webhook credential, principal, clone URL, or deployment
target is selected from unverified body data.

## TDD evidence

### Red

The new handler integration tests were written before the handler integration
constructor and boundary existed:

```text
$ /usr/local/go/bin/go test -count=1 -run 'TestHandleWebhook' -v
./handler_test.go:86:13: undefined: NewWebhookDeployer
./handler_test.go:243:14: undefined: NewWebhookDeployer
./handler_test.go:255:7: undefined: DeploymentExecutor
FAIL    gitea-pages-deployer [build failed]
```

### Green

After the minimal handler, dependency wiring, and error mapping changes:

```text
$ /usr/local/go/bin/go test -count=1 -run 'TestHandleWebhook' -v
PASS
ok      gitea-pages-deployer
```

The focused tests cover canonical deployment invocation while ignoring a body
clone URL, verified deletion, cross-tenant private-repository IDOR rejection
before deployment, replay rejection, unknown/Bearer authorization rejection,
429 with `Retry-After: 30`, malformed payload 400, repository-size 413, and
method handling.

## Full and race verification

```text
$ /usr/local/go/bin/go test -count=1 ./...
ok      gitea-pages-deployer  0.384s

$ /usr/local/go/bin/go test -count=1 -race ./...
ok      gitea-pages-deployer  1.918s

$ git diff --check
# no output; exit 0
```

## Self-review

- The payload is decoded only after per-hook HMAC verification and replay
  recording. Bearer/Base64 user selection is no longer accepted by the
  handler or emitted by OAuth registration.
- The authenticated hook principal, not payload ownership, selects the OAuth
  token used for canonical Gitea lookup. Out-of-scope, mismatched, inaccessible,
  and untrusted repositories map to 403 before the deployment boundary.
- Deployment receives the canonical clone URL and a `SiteTarget` made from
  canonical owner/name. The raw-clone `DeployWithToken` entry point and global
  deployment token fallback were removed.
- Unknown/malformed authentication and event inputs map to 401/400; oversized
  payloads and repositories map to 413; saturated deployment capacity maps to
  429 with exactly `Retry-After: 30`; unexpected failures map to 5xx.
- Push branch deletion and `delete` branch events remove only verified
  `gh-pages` targets. Tag deletion is ignored.
- Runtime config no longer loads `WEBHOOK_SECRET` or
  `LEGACY_WEBHOOK_SECRET_FILE`, and legacy auto-registration was removed.
  Task 10's offline migration/rollback code remains the sole legacy-secret
  mechanism.
