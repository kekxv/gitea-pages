//go:build !linux

package main

func exchangeSitePaths(_, _ string) error {
	return ErrAtomicPublicationUnsupported
}
