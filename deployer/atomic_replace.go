package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

var ErrAtomicPublicationUnsupported = errors.New("atomic replacement of an existing site is unsupported on this platform")

// replaceSiteAtomically publishes staging without ever leaving an existing
// target absent. On Linux it uses renameat2(RENAME_EXCHANGE), which atomically
// swaps the names before the old site is cleaned up.
func replaceSiteAtomically(staging string, target SiteTarget) error {
	return replaceSiteAtomicallyWithExchange(staging, target, exchangeSitePaths)
}

func replaceSiteAtomicallyWithExchange(staging string, target SiteTarget, exchange func(string, string) error) error {
	if err := target.validateExistingPath(); err != nil {
		return err
	}
	parent := filepath.Dir(target.Path())
	stagingAbs, err := filepath.Abs(staging)
	if err != nil {
		return fmt.Errorf("resolve deployment staging directory: %w", err)
	}
	if filepath.Dir(stagingAbs) != parent {
		return fmt.Errorf("staging directory: %w", ErrUnsafeSiteTarget)
	}
	stagingInfo, err := os.Lstat(stagingAbs)
	if err != nil {
		return fmt.Errorf("inspect deployment staging directory: %w", err)
	}
	if !stagingInfo.IsDir() || stagingInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("staging directory: %w", ErrUnsafeSiteTarget)
	}

	targetInfo, err := os.Lstat(target.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return os.Rename(stagingAbs, target.Path())
	}
	if err != nil {
		return fmt.Errorf("inspect existing site: %w", err)
	}
	if targetInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("site target: %w", ErrUnsafeSiteTarget)
	}
	if err := exchange(stagingAbs, target.Path()); err != nil {
		return fmt.Errorf("atomically exchange site: %w", err)
	}
	if err := os.RemoveAll(stagingAbs); err != nil {
		return fmt.Errorf("remove exchanged previous site: %w", err)
	}
	return nil
}
