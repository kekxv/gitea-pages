package main

import "errors"

var ErrAtomicPublicationUnsupported = errors.New("atomic replacement of an existing site is unsupported on this platform")
