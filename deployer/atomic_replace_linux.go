//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type exchangeSitePathsFunc func(int, string, string) error

const secureDirectoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW

// replaceSiteAtomically publishes names only within a descriptor retained for
// the trusted owner directory. This closes the Lstat-to-rename substitution
// window even if a caller later races on the original path strings.
func replaceSiteAtomically(staging string, target SiteTarget) error {
	return replaceSiteAtomicallyWithExchange(staging, target, exchangeSitePaths)
}

func replaceSiteAtomicallyWithExchange(staging string, target SiteTarget, exchange exchangeSitePathsFunc) error {
	parentFD, stagingName, targetName, stagingAbs, targetExists, err := securePublicationEntries(staging, target)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)

	if !targetExists {
		if err := unix.Renameat(parentFD, stagingName, parentFD, targetName); err != nil {
			return fmt.Errorf("publish initial site: %w", err)
		}
		return nil
	}
	if err := exchange(parentFD, stagingName, targetName); err != nil {
		return fmt.Errorf("atomically exchange site: %w", normalizeAtomicPublicationError(err))
	}
	if err := os.RemoveAll(stagingAbs); err != nil {
		return fmt.Errorf("remove exchanged previous site: %w", err)
	}
	return nil
}

// ensureSecurePublicationParent creates the owner directory only beneath a
// trusted Pages root. The root and owner must be owned by root or this process
// and must not be writable by group or other users.
func ensureSecurePublicationParent(target SiteTarget) error {
	rootFD, err := openTrustedPagesRoot(target)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	ownerFD, err := openTrustedDirectoryAt(rootFD, target.owner)
	if errors.Is(err, unix.ENOENT) {
		if err := unix.Mkdirat(rootFD, target.owner, 0755); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("create deployment owner directory: %w", err)
		}
		ownerFD, err = openTrustedDirectoryAt(rootFD, target.owner)
	}
	if err != nil {
		return fmt.Errorf("open deployment owner directory: %w", err)
	}
	return unix.Close(ownerFD)
}

// removeSiteSecurely removes a site by names relative to a retained owner
// descriptor. The descriptor continues to identify the trusted owner even if
// an attacker later substitutes a symlink into the original path.
func removeSiteSecurely(target SiteTarget) error {
	return removeSiteSecurelyWithAfterParentOpen(target, nil)
}

// removeSiteSecurelyWithAfterParentOpen has an internal hook so the
// post-validation substitution regression can exercise the exact window that
// descriptor-relative deletion closes. Production callers always pass nil.
func removeSiteSecurelyWithAfterParentOpen(target SiteTarget, afterParentOpen func() error) error {
	parentFD, err := openTrustedPublicationParent(target)
	if err != nil {
		return normalizeSecureDeletionError(err)
	}
	defer unix.Close(parentFD)

	if afterParentOpen != nil {
		if err := afterParentOpen(); err != nil {
			return err
		}
	}

	targetName := filepath.Base(target.Path())
	for attempts := 0; attempts < 16; attempts++ {
		tombstoneName, err := secureDeletionTombstoneName()
		if err != nil {
			return fmt.Errorf("generate deletion tombstone name: %w", err)
		}
		err = unix.Renameat2(parentFD, targetName, parentFD, tombstoneName, unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return fmt.Errorf("move site into deletion tombstone: %w", normalizeSecureDeletionError(err))
		}
		if err := removeSiteEntryAt(parentFD, tombstoneName); err != nil {
			return fmt.Errorf("remove site deletion tombstone: %w", err)
		}
		return nil
	}
	return fmt.Errorf("generate unique deletion tombstone: %w", ErrUnsafeSiteTarget)
}

func secureDeletionTombstoneName() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return ".deleting-" + hex.EncodeToString(random[:]), nil
}

// removeSiteEntryAt recursively removes a single entry using directory file
// descriptors only. Fstatat and Openat2 both refuse to resolve symlinks; a
// symlink (or any other non-directory) is unlinked as the entry itself.
func removeSiteEntryAt(parentFD int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(parentFD, name, 0)
	}

	childFD, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   uint64(secureDirectoryFlags),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	if err != nil {
		return normalizeSecureDeletionError(err)
	}
	directory := os.NewFile(uintptr(childFD), "site-deletion")
	entries, readErr := directory.ReadDir(-1)
	if readErr == nil {
		for _, entry := range entries {
			if err := removeSiteEntryAt(childFD, entry.Name()); err != nil {
				readErr = err
				break
			}
		}
	}
	closeErr := directory.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}

func securePublicationEntries(staging string, target SiteTarget) (int, string, string, string, bool, error) {
	if err := target.validateExistingPath(); err != nil {
		return -1, "", "", "", false, err
	}
	stagingAbs, err := filepath.Abs(staging)
	if err != nil {
		return -1, "", "", "", false, fmt.Errorf("resolve deployment staging directory: %w", err)
	}
	if filepath.Dir(stagingAbs) != filepath.Dir(target.Path()) {
		return -1, "", "", "", false, fmt.Errorf("staging directory: %w", ErrUnsafeSiteTarget)
	}
	parentFD, err := openTrustedPublicationParent(target)
	if err != nil {
		return -1, "", "", "", false, err
	}
	stagingName := filepath.Base(stagingAbs)
	targetName := filepath.Base(target.Path())
	if err := requireDirectoryAt(parentFD, stagingName); err != nil {
		unix.Close(parentFD)
		return -1, "", "", "", false, fmt.Errorf("staging directory: %w", err)
	}
	targetExists, err := directoryExistsAt(parentFD, targetName)
	if err != nil {
		unix.Close(parentFD)
		return -1, "", "", "", false, fmt.Errorf("site target: %w", err)
	}
	return parentFD, stagingName, targetName, stagingAbs, targetExists, nil
}

func openTrustedPublicationParent(target SiteTarget) (int, error) {
	rootFD, err := openTrustedPagesRoot(target)
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootFD)
	ownerFD, err := openTrustedDirectoryAt(rootFD, target.owner)
	if err != nil {
		return -1, fmt.Errorf("open deployment owner directory: %w", err)
	}
	return ownerFD, nil
}

func openTrustedPagesRoot(target SiteTarget) (int, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, target.root, &unix.OpenHow{
		Flags:   uint64(secureDirectoryFlags),
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, normalizeSecureDirectoryOpenError("Pages root", err)
	}
	if err := requireTrustedDirectory(fd); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("Pages root: %w", err)
	}
	return fd, nil
}

func openTrustedDirectoryAt(parentFD int, name string) (int, error) {
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   uint64(secureDirectoryFlags),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	if err != nil {
		return -1, normalizeSecureDirectoryOpenError("directory", err)
	}
	if err := requireTrustedDirectory(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func requireDirectoryAt(parentFD int, name string) error {
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   uint64(secureDirectoryFlags),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	if err != nil {
		return normalizeSecureDirectoryOpenError("directory entry", err)
	}
	return unix.Close(fd)
}

func directoryExistsAt(parentFD int, name string) (bool, error) {
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   uint64(secureDirectoryFlags),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, normalizeSecureDirectoryOpenError("site target", err)
	}
	return true, unix.Close(fd)
}

func requireTrustedDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&(unix.S_IWGRP|unix.S_IWOTH) != 0 {
		return ErrUnsafeSiteTarget
	}
	euid := uint32(os.Geteuid())
	if stat.Uid != 0 && stat.Uid != euid {
		return ErrUnsafeSiteTarget
	}
	return nil
}

func exchangeSitePaths(parentFD int, stagingName, targetName string) error {
	return unix.Renameat2(parentFD, stagingName, parentFD, targetName, unix.RENAME_EXCHANGE)
}

func normalizeSecureDirectoryOpenError(subject string, err error) error {
	if normalized := normalizeAtomicPublicationError(err); errors.Is(normalized, ErrAtomicPublicationUnsupported) {
		return normalized
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EXDEV) {
		return fmt.Errorf("%s: %w", subject, ErrUnsafeSiteTarget)
	}
	return err
}

func normalizeSecureDeletionError(err error) error {
	if errors.Is(err, ErrAtomicPublicationUnsupported) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("%w: %v", ErrSecureDeletionUnsupported, err)
	}
	return err
}

func normalizeAtomicPublicationError(err error) error {
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("%w: %v", ErrAtomicPublicationUnsupported, err)
	}
	return err
}
