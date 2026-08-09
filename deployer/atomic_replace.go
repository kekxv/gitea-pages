package main

import "errors"

var ErrAtomicPublicationUnsupported = errors.New("atomic replacement of an existing site is unsupported on this platform")

var ErrSecureDeletionUnsupported = errors.New("secure site deletion is unsupported on this platform")
