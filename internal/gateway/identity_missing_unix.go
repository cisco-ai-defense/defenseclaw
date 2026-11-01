// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"errors"
	osuser "os/user"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// definitiveMissingAccount reports a directory lookup error that says the uid
// has no account: the NSS resolver's not-found, or os/user's unknown uid. The
// cache keeps it visible because a local NSS answer does not prove a remote
// directory is healthy (GAP-0696, GAP-0712).
func definitiveMissingAccount(err error) bool {
	var unknown osuser.UnknownUserIdError
	return unixidentity.IsNotFound(err) || errors.As(err, &unknown)
}

// missingAccountDirectoryAway reports a directory that does not answer now,
// so the "no such account" a lookup of key got is not definitive: the hook
// guardian lists a domain away (directoryUnreachable), or Open Directory
// lists its Active Directory node offline (macOS). A bound Mac answers "no
// such account" for a directory account it holds in no cache while its
// domain controllers do not answer, and health took a new user's failed
// lookup during the outage for an account that does not exist, so the state
// stayed ok (status-v2 GAP-0011). Tests replace it.
var missingAccountDirectoryAway = func(string, time.Time) bool {
	return directoryUnreachable("") || directoryNodeOffline()
}

// Local NSS answers cannot confirm a remote account has gone.
func reliableMissingAccountConfirmation() bool { return false }
