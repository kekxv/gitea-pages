//go:build !linux

package main

import (
	"errors"
	"testing"
)

func TestRemoveSiteReportsSecureDeletionUnsupportedOutsideLinux(t *testing.T) {
	pagesRoot := t.TempDir()
	target, err := NewSiteTarget(pagesRoot, "alice", "site", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	err = (&GitOperations{pagesDir: pagesRoot}).RemoveSite(target)
	if !errors.Is(err, ErrSecureDeletionUnsupported) {
		t.Fatalf("RemoveSite error = %v, want secure deletion unsupported", err)
	}
}
