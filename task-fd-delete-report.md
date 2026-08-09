# Descriptor-relative site deletion report

`GitOperations.RemoveSite` no longer passes a validated site path to `os.RemoveAll`.

On Linux it opens the trusted Pages root and owner directory with `openat2`, keeps the owner descriptor open, atomically moves the target leaf to a random tombstone with `renameat2(RENAME_NOREPLACE)`, and recursively removes that tombstone only through `fstatat`, `openat2`, and `unlinkat` calls relative to retained descriptors. Symlinks are never resolved during deletion.

The new Linux regression substitutes the validated owner path for a symlink to an outside directory after the trusted descriptor has been opened. The external sentinel remains intact while the original detached site is removed. The Pages root and owner trust checks already used for atomic publication are reused, so group/world-writable or untrusted roots/owners are refused. Non-Linux builds return `ErrSecureDeletionUnsupported` rather than falling back to path-based deletion.

Verification performed in `deployer` with Go 1.26:

- `go test -run TestRemoveSiteDoesNotFollowAncestorSymlinkSubstitutionAfterValidation -count=1 -v`
- `go test ./... -count=1`
- `go test -race ./... -count=1`
- `GOOS=darwin GOARCH=amd64 go test -c -o /tmp/deployer-darwin.test`
