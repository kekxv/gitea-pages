//go:build linux

package main

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// This would fail if a kernel or filesystem lacking atomic exchange surfaced
// as an ambiguous low-level error instead of an explicit unsupported result.
func TestNormalizeAtomicPublicationUnsupportedErrors(t *testing.T) {
	for _, err := range []error{unix.ENOSYS, unix.EOPNOTSUPP, unix.EINVAL} {
		if got := normalizeAtomicPublicationError(err); !errors.Is(got, ErrAtomicPublicationUnsupported) {
			t.Fatalf("normalizeAtomicPublicationError(%v) = %v, want unsupported", err, got)
		}
	}
}
