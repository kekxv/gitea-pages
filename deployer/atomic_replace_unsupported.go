//go:build !linux

package main

type exchangeSitePathsFunc func(int, string, string) error

func replaceSiteAtomically(string, SiteTarget) error {
	return ErrAtomicPublicationUnsupported
}

func replaceSiteAtomicallyWithExchange(string, SiteTarget, exchangeSitePathsFunc) error {
	return ErrAtomicPublicationUnsupported
}

func ensureSecurePublicationParent(SiteTarget) error {
	return ErrAtomicPublicationUnsupported
}

func removeSiteSecurely(SiteTarget) error {
	return ErrSecureDeletionUnsupported
}
