// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package useridentity resolves the end-user join keys DefenseClaw attaches to
// v8 telemetry: the OS account identifier (a Windows SID or a POSIX uid), the
// OS account name, and — where an agent stores one locally — the signed-in
// account email.
//
// Two callers want different things from this package, and conflating them is
// the mistake it exists to prevent. A hook runs inside the real user's session
// and asks for Current(). The gateway sidecar does not: under a managed
// install it runs as a service account, so asking it who "the" user is would
// attribute every event on the endpoint to that one service identity. The
// sidecar resolves identity per user profile directory with ForHome.
//
// Nothing here is identity attestation. These are attribution join keys read
// from the OS and from agent-owned config files, and any other process running
// as the same user can influence the file-derived parts. Never promote a value
// from this package to an authorization decision.
package useridentity

import "strings"

const (
	// KindWindowsSID and KindPOSIXUID are the two members of the v8
	// defenseclaw.user.id_kind enum. They travel next to user.id so a
	// consumer knows how to interpret it instead of inferring from shape.
	KindWindowsSID = "windows_sid"
	KindPOSIXUID   = "posix_uid"
)

// maxIDLength bounds an identifier before it is classified or emitted. A SID
// is well under this; anything longer is not an identifier we can vouch for.
const maxIDLength = 256

// Identity is one end user, as far as the endpoint can observe.
//
// Every field is optional and an empty Identity is an ordinary outcome: a
// profile directory with no resolvable owner, or an agent with no local
// credential. Callers emit the fields that resolved and omit the rest rather
// than substituting a placeholder, because a wrong user attribution is worse
// than an absent one.
type Identity struct {
	// ID is the SID on Windows and the uid on POSIX.
	ID string
	// IDKind is KindWindowsSID, KindPOSIXUID, or empty when ID came from a
	// source that does not establish which of the two it is.
	IDKind string
	// Name is the bare OS account name, never DOMAIN\user, so it cannot be
	// mistaken for a qualified principal or an email.
	Name string
	// Email is the signed-in account an agent recorded locally. It is
	// populated only by EmailForConnector, never by the OS lookups.
	Email string
}

// Empty reports whether nothing resolved at all.
func (i Identity) Empty() bool {
	return i.ID == "" && i.Name == "" && i.Email == ""
}

// Current reports the OS identity of the calling process.
//
// Call this only from a process that already runs as the end user — a hook.
// Calling it from the gateway sidecar under a managed install reports the
// service account, which is precisely the misattribution this package is
// meant to prevent.
func Current() Identity {
	return currentIdentity()
}

// ForHome reports the owner of one user profile directory.
//
// This is the sidecar's path. The gateway walks every profile root on the
// endpoint, so it needs the owner of the directory the evidence came from, not
// the owner of its own process.
func ForHome(home string) Identity {
	home = strings.TrimSpace(home)
	if home == "" {
		return Identity{}
	}
	return identityForHome(home)
}

// HomeForID reports the profile directory belonging to an OS user id.
//
// This is the inverse of ForHome and closes the loop for the gateway: a hook
// reports who it ran as, and the gateway needs that user's profile to read the
// connector credential that names their signed-in account. Resolving the
// directory from the id keeps the hook from naming a path itself, which would
// let it point the gateway at another user's files.
func HomeForID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > maxIDLength || KindForID(id) == "" {
		return ""
	}
	return homeForID(id)
}

// KindForID classifies an identifier collected somewhere else — a hook's
// identity header, or an agent-supplied hook payload field.
//
// It returns empty for anything it cannot place. That matters: a payload may
// carry an arbitrary string such as a login name, and labelling that
// posix_uid would put a value into the v8 enum that consumers would then
// join on as a uid. Absent is the honest answer.
func KindForID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > maxIDLength {
		return ""
	}
	if isWindowsSID(id) {
		return KindWindowsSID
	}
	if isPOSIXUID(id) {
		return KindPOSIXUID
	}
	return ""
}

// isWindowsSID recognizes the SDDL string form, S-R-I(-S)+, without accepting
// the shorthand aliases (for example "BA") that also appear in SDDL but are
// not identifiers.
func isWindowsSID(id string) bool {
	if !strings.HasPrefix(id, "S-") && !strings.HasPrefix(id, "s-") {
		return false
	}
	parts := strings.Split(id, "-")
	// S, revision, identifier authority, and at least one subauthority.
	if len(parts) < 4 {
		return false
	}
	for _, part := range parts[1:] {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// isPOSIXUID recognizes a decimal uid. Leading zeros are rejected because a
// uid is not zero-padded, and accepting them would let "007" and "7" join as
// two different users.
func isPOSIXUID(id string) bool {
	if len(id) > 1 && id[0] == '0' {
		return false
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(id) > 0
}
