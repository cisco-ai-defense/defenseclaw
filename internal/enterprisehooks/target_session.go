// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// WindowsTargetSessionUnavailableError identifies the one session condition
// an administrator-authored deferred target may treat as pending. Other WTS,
// token, profile, and privilege failures remain ordinary hard errors.
type WindowsTargetSessionUnavailableError struct {
	SID string
}

func (e *WindowsTargetSessionUnavailableError) Error() string {
	sid := strings.TrimSpace(e.SID)
	if sid == "" {
		sid = "<unknown>"
	}
	return fmt.Sprintf(
		"enterprise hooks: no active interactive session token matches explicit target SID %s; guardian will retry",
		sid,
	)
}

// windowsSessionState is one WTS session: its ID and connection state.
type windowsSessionState struct {
	ID           uint32
	Active       bool
	Disconnected bool
}

// windowsTargetSessionOrder is the order in which a target's session tokens
// are tried: the active sessions, then, when allowDisconnected is set, the
// disconnected ones, each in session ID order. A disconnected session keeps
// its user signed in, and managed ACP enrollment refused such a user as
// having no signed-in session (GAP-0835).
func windowsTargetSessionOrder(sessions []windowsSessionState, allowDisconnected bool) []uint32 {
	var active, disconnected []uint32
	for _, session := range sessions {
		switch {
		case session.Active:
			active = append(active, session.ID)
		case session.Disconnected && allowDisconnected:
			disconnected = append(disconnected, session.ID)
		}
	}
	slices.Sort(active)
	slices.Sort(disconnected)
	return append(active, disconnected...)
}

// IsWindowsTargetSessionUnavailable reports only the typed absence case. It
// deliberately does not classify errors by text, so access-denied, WTS query,
// token-validation, and profile-mismatch failures cannot be downgraded.
func IsWindowsTargetSessionUnavailable(err error) bool {
	var unavailable *WindowsTargetSessionUnavailableError
	return errors.As(err, &unavailable)
}

// RequireWindowsEnterpriseDeferredTargetPending proves that an enabled,
// administrator-authored deferred row has no selected immutable runtime for
// its exact SID and connector. A caller may report the row as pending only
// after both this proof and an exact WTS-session absence proof succeed.
func RequireWindowsEnterpriseDeferredTargetPending(target ManifestTarget) error {
	return requireWindowsEnterpriseDeferredTargetPendingPlatform(target)
}
