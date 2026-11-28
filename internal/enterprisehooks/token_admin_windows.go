//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// WindowsTokenAdminFacts are the two token queries behind "is this an
// elevated administrator or LocalSystem": TokenElevation and the token user.
// Each keeps its own query error, so a caller can tell a token known to be
// standard (both queries answered, neither privileged) from one the queries
// could not read. windows.Token.IsElevated reads a failed query as "not
// elevated", which made a privileged writer skip its file lock (GAP-1894).
type WindowsTokenAdminFacts struct {
	Elevated     bool
	ElevationErr error
	LocalSystem  bool
	UserErr      error
}

// CurrentWindowsTokenAdminFacts queries the current process token.
func CurrentWindowsTokenAdminFacts() WindowsTokenAdminFacts {
	token := windows.GetCurrentProcessToken()
	var facts WindowsTokenAdminFacts
	if elevation, err := windowsEnterpriseTokenUint32(token, windows.TokenElevation); err != nil {
		facts.ElevationErr = err
	} else {
		facts.Elevated = elevation != 0
	}
	user, err := token.GetTokenUser()
	switch {
	case err != nil:
		facts.UserErr = err
	case user == nil || user.User.Sid == nil:
		facts.UserErr = errors.New("token user has no SID")
	default:
		facts.LocalSystem = user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
	}
	return facts
}

// ElevatedOrSystem reports whether the token is an elevated administrator or
// LocalSystem. One positive answer is enough. false with a nil error means
// both queries answered and neither holds; an error means the token may be
// privileged but the queries could not say.
func (f WindowsTokenAdminFacts) ElevatedOrSystem() (bool, error) {
	if (f.ElevationErr == nil && f.Elevated) || (f.UserErr == nil && f.LocalSystem) {
		return true, nil
	}
	if f.ElevationErr != nil {
		return false, fmt.Errorf("read token elevation: %w", f.ElevationErr)
	}
	if f.UserErr != nil {
		return false, fmt.Errorf("read token user: %w", f.UserErr)
	}
	return false, nil
}
