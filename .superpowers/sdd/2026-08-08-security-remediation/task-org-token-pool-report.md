# Organization administrator token-pool hardening

## Delivered

- The canonical repository verifier now rejects expired OAuth tokens rather
  than using them for a Gitea API request.
- For an authenticated organization hook only, when its original authorizer
  has no usable token, the verifier reads the already-persisted administrator
  pool for that same organization and selects the first usable stored token.
- User-scoped hooks remain bound to their own principal token; they never
  consult an organization pool.
- The pool lookup is scoped by the authenticated hook's `ScopeName`, so an
  administrator recorded for another organization cannot supply a token.
- `VerifiedRepository.AccessToken` is the selected usable token, matching the
  bearer token used for the canonical Gitea lookup.

## TDD evidence

The repository-verifier regression test was added first. Before the verifier
change it failed in both required unavailable-principal cases:

```text
expired token: repository lookup authorization = "Bearer expired-principal-token", want "Bearer administrator-token"
expired token: verified repository access token = "expired-principal-token", want "administrator-token"
missing token: verify repository: no access token for webhook principal
```

The same test verifies both unavailable cases, and separate regressions prove
that user hooks cannot fall back and that no other-organization administrator
is used.

## Verification

```text
cd deployer && /usr/local/go/bin/go test . -count=1
ok      gitea-pages-deployer  0.915s

cd deployer && /usr/local/go/bin/go test -race . -count=1
ok      gitea-pages-deployer  3.008s

git diff --check
# no output; exit 0
```

## Round 1 — early organization-scope rejection

The verifier now rejects an organization-hook payload whose owner differs
from the authenticated principal's organization before it consults the
administrator pool or creates a Gitea client. This keeps an untrusted payload
from causing an otherwise authorized administrator token to be used outside
its canonical organization scope.

TDD regression evidence:

```text
Before the guard:
canonical Gitea requests = 1, want 0

After the guard:
cd deployer && /usr/local/go/bin/go test . -run TestVerifyOrganizationHookRejectsCrossOwnerBeforeAdministratorTokenFallback -count=1
ok      gitea-pages-deployer
```

The test uses a missing original authorizer token plus a valid same-organization
administrator pool entry, then supplies `victim` as the payload owner. It
asserts `ErrRepositoryOutOfScope` and zero fake-Gitea requests.

Fresh full verification:

```text
cd deployer && /usr/local/go/bin/go test . -count=1
ok      gitea-pages-deployer  0.910s

cd deployer && /usr/local/go/bin/go test -race . -count=1
ok      gitea-pages-deployer  3.049s
```
