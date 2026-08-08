//go:build linux

package main

import "golang.org/x/sys/unix"

func exchangeSitePaths(staging, target string) error {
	return unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, target, unix.RENAME_EXCHANGE)
}
