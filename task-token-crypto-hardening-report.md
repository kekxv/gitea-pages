# Token crypto hardening report

Implemented the deferred token-crypto hardening on top of Task 5.

- AES-GCM token ciphertext now authenticates the normalized username and the
  token field (`access` or `refresh`) as associated data.
- New token writes and the offline security migration emit AAD-bound version 2
  records. Existing version 1 encrypted records remain readable and are
  transactionally re-keyed to version 2 at startup.
- `TokenStore.Set` now returns persistence errors and leaves in-memory state
  unchanged on failure. OAuth callbacks fail with HTTP 500 before webhook
  registration or session issuance when token persistence fails.

Tests added cover nonce uniqueness, wrong-key rejection, user/field ciphertext
swaps, legacy encrypted reads and re-keying, migration output versioning, and
callback persistence failure.

Verification:

- `/usr/local/go/bin/go test ./...`
- `/usr/local/go/bin/go test -race ./...`
