// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A managed per-user folder (%USERPROFILE%\.defenseclaw and its hooks child)
// carries the exact canonical protected DACL. Another product can add a grant
// of its own there: OpenAI Codex's Windows sandbox gives its local
// CodexSandboxUsers group read and execute (0x1200a9, inherited by new
// children) on the folders its sandboxed processes read, DefenseClaw's
// included. That grant cannot change, delete or re-permission anything, so it
// does not weaken the folder's integrity. Refusing it failed every hook and
// every reinstall of the account ("has 8 ACEs, expected 7"), and stripping it
// only had the guardian and Codex take turns rewriting the folder.
//
// The access rights such an extra grant may carry are exactly these read
// rights; any other bit (any write-like right below, ACCESS_SYSTEM_SECURITY,
// MAXIMUM_ALLOWED or an unknown bit) keeps the grant refused.
const (
	windowsACEFileReadData       uint32 = 0x00000001 // FILE_READ_DATA / FILE_LIST_DIRECTORY
	windowsACEFileReadEA         uint32 = 0x00000008 // FILE_READ_EA
	windowsACEFileExecute        uint32 = 0x00000020 // FILE_EXECUTE / FILE_TRAVERSE
	windowsACEFileReadAttributes uint32 = 0x00000080 // FILE_READ_ATTRIBUTES
	windowsACEReadControl        uint32 = 0x00020000 // READ_CONTROL
	windowsACESynchronize        uint32 = 0x00100000 // SYNCHRONIZE
	windowsACEGenericExecute     uint32 = 0x20000000 // GENERIC_EXECUTE
	windowsACEGenericRead        uint32 = 0x80000000 // GENERIC_READ

	windowsReadOnlyGrantMask = windowsACEFileReadData |
		windowsACEFileReadEA |
		windowsACEFileExecute |
		windowsACEFileReadAttributes |
		windowsACEReadControl |
		windowsACESynchronize |
		windowsACEGenericExecute |
		windowsACEGenericRead

	// windowsWriteLikeGrantMask documents the rights a read-only grant never
	// carries: FILE_WRITE_DATA/ADD_FILE, FILE_APPEND_DATA/ADD_SUBDIRECTORY,
	// FILE_WRITE_EA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, DELETE,
	// WRITE_DAC, WRITE_OWNER, GENERIC_ALL and GENERIC_WRITE.
	windowsWriteLikeGrantMask uint32 = 0x00000002 | 0x00000004 | 0x00000010 |
		0x00000040 | 0x00000100 | 0x00010000 | 0x00040000 | 0x00080000 |
		0x10000000 | 0x40000000
)

const (
	windowsACEAccessAllowedType uint8 = 0x00
	// OBJECT_INHERIT, CONTAINER_INHERIT, NO_PROPAGATE_INHERIT and
	// INHERIT_ONLY. INHERITED_ACE (0x10) and the audit flags are not allowed
	// on an extra grant: the managed DACL is protected.
	windowsACEExplicitInheritFlags uint8 = 0x0f
)

// windowsReadOnlyAccessMask reports whether mask grants only read rights
// (windowsReadOnlyGrantMask) and at least one of them.
func windowsReadOnlyAccessMask(mask uint32) bool {
	return mask != 0 && mask&^windowsReadOnlyGrantMask == 0
}

// windowsDACLEntry is one ACE of a DACL, with its SID in string form.
type windowsDACLEntry struct {
	aceType uint8
	flags   uint8
	mask    uint32
	sid     string
}

// windowsDACLExpectedEntry is one canonical ACE as Windows stores it.
type windowsDACLExpectedEntry struct {
	sid   string
	mask  uint32
	flags uint8
}

// windowsReadOnlyExtraReservedSID reports whether sid is a principal the
// canonical DACL already names, or one with owner semantics: an extra ACE for
// it is never a tolerated read-only grant (a changed or duplicated canonical
// entry is drift, not another product's grant).
func windowsReadOnlyExtraReservedSID(sid, target string) bool {
	sid = strings.TrimSpace(sid)
	for _, reserved := range []string{
		target,
		"S-1-5-18",     // LocalSystem
		"S-1-5-32-544", // BUILTIN\Administrators
		"S-1-3-4",      // OWNER RIGHTS
		"S-1-3-0",      // CREATOR OWNER
	} {
		if strings.EqualFold(sid, strings.TrimSpace(reserved)) {
			return true
		}
	}
	return false
}

// windowsReadOnlyExtraBroadPrincipals are well-known groups that cover every
// user, every logon of a kind (Windows adds the Dialup, Network, Batch,
// Interactive and Service groups to the token of every such logon), or every
// app container. An agent sandbox grants
// its own group, never one of these, so a read grant to one is not tolerated.
var windowsReadOnlyExtraBroadPrincipals = map[string]bool{
	"S-1-1-0":      true, // Everyone
	"S-1-2-0":      true, // Local
	"S-1-2-1":      true, // Console Logon
	"S-1-5-1":      true, // Dialup
	"S-1-5-2":      true, // Network
	"S-1-5-3":      true, // Batch
	"S-1-5-4":      true, // Interactive
	"S-1-5-6":      true, // Service
	"S-1-5-7":      true, // Anonymous Logon
	"S-1-5-11":     true, // Authenticated Users
	"S-1-5-14":     true, // Remote Interactive Logon
	"S-1-5-113":    true, // Local account
	"S-1-5-114":    true, // Local account and member of Administrators group
	"S-1-5-32-545": true, // Users
	"S-1-5-32-546": true, // Guests
	"S-1-5-32-547": true, // Power Users
	"S-1-5-32-555": true, // Remote Desktop Users
	"S-1-15-2-1":   true, // ALL APPLICATION PACKAGES
	"S-1-15-2-2":   true, // ALL RESTRICTED APPLICATION PACKAGES
}

// windowsReadOnlyExtraBroadSID reports whether sid is a broad group: one of
// windowsReadOnlyExtraBroadPrincipals, or Domain Users (513) or Domain Guests
// (514) under any S-1-5-21-<a>-<b>-<c> domain.
func windowsReadOnlyExtraBroadSID(sid string) bool {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	if windowsReadOnlyExtraBroadPrincipals[sid] {
		return true
	}
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		return false
	}
	parts := strings.Split(sid, "-")
	return len(parts) == 8 && (parts[7] == "513" || parts[7] == "514")
}

// windowsReadOnlyExtraACE reports whether entry is an extra grant a managed
// folder may carry: an explicit access-allowed ACE whose rights are all read
// rights, for a principal the canonical DACL does not name and that is not a
// broad group.
func windowsReadOnlyExtraACE(entry windowsDACLEntry, target string) bool {
	return entry.aceType == windowsACEAccessAllowedType &&
		entry.flags&^windowsACEExplicitInheritFlags == 0 &&
		windowsReadOnlyAccessMask(entry.mask) &&
		strings.TrimSpace(entry.sid) != "" &&
		!windowsReadOnlyExtraReservedSID(entry.sid, target) &&
		!windowsReadOnlyExtraBroadSID(entry.sid)
}

// windowsReadOnlyExtraTolerantPath reports whether path names a folder that
// may carry read-only extra grants: a profile's .defenseclaw data folder or
// its hooks child. Files and every other managed folder keep the exact DACL.
func windowsReadOnlyExtraTolerantPath(path string) bool {
	clean := strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(path), "/", `\`), `\`)
	parts := strings.Split(clean, `\`)
	count := len(parts)
	// The folder's parent (the profile) must be a real path element.
	plain := func(part string) bool { return part != "" && part != "." && part != ".." }
	switch {
	case count >= 2 && strings.EqualFold(parts[count-1], ".defenseclaw"):
		return plain(parts[count-2])
	case count >= 3 && strings.EqualFold(parts[count-1], "hooks") && strings.EqualFold(parts[count-2], ".defenseclaw"):
		return plain(parts[count-3])
	}
	return false
}

// windowsReadOnlyExtraACEsTolerated reports whether the managed DACL check of
// path accepts read-only extra grants. DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS=1
// keeps the exact DACL everywhere.
func windowsReadOnlyExtraACEsTolerated(path string, directory bool) bool {
	return directory && windowsReadOnlyExtraTolerantPath(path) && !managed.TrustStrictAncestors()
}

// windowsDACLMatchFailure says why a DACL is not the canonical one.
type windowsDACLMatchFailure int

const (
	windowsDACLMatched windowsDACLMatchFailure = iota
	// windowsDACLCountMismatch: exact matching found a different ACE count.
	windowsDACLCountMismatch
	// windowsDACLNonAllowedType: an ACE is not an access-allowed ACE.
	windowsDACLNonAllowedType
	// windowsDACLUnexpectedEntry: an ACE is neither canonical nor a
	// tolerated read-only grant.
	windowsDACLUnexpectedEntry
	// windowsDACLMissingCanonical: a canonical ACE is absent.
	windowsDACLMissingCanonical
)

// windowsDACLMatch is the outcome of matchWindowsCanonicalDACL.
type windowsDACLMatch struct {
	failure windowsDACLMatchFailure
	// index is the offending entry for NonAllowedType and UnexpectedEntry.
	index int
	// extras are the indexes of the tolerated read-only grants.
	extras []int
}

// matchWindowsCanonicalDACL matches entries against the canonical expected
// set: every expected ACE exactly once (SID, mask and flags), in any order.
// Without tolerateReadOnly nothing else is allowed; with it, the only other
// entries allowed are read-only grants (windowsReadOnlyExtraACE) for other
// principals than target.
func matchWindowsCanonicalDACL(
	entries []windowsDACLEntry,
	expected []windowsDACLExpectedEntry,
	target string,
	tolerateReadOnly bool,
) windowsDACLMatch {
	if !tolerateReadOnly && len(entries) != len(expected) {
		return windowsDACLMatch{failure: windowsDACLCountMismatch, index: -1}
	}
	seen := make([]bool, len(expected))
	var extras []int
	for index, entry := range entries {
		if entry.aceType != windowsACEAccessAllowedType {
			return windowsDACLMatch{failure: windowsDACLNonAllowedType, index: index}
		}
		match := -1
		for candidate, want := range expected {
			if !seen[candidate] &&
				strings.EqualFold(entry.sid, want.sid) &&
				entry.mask == want.mask &&
				entry.flags == want.flags {
				match = candidate
				break
			}
		}
		if match >= 0 {
			seen[match] = true
			continue
		}
		if tolerateReadOnly && windowsReadOnlyExtraACE(entry, target) {
			extras = append(extras, index)
			continue
		}
		return windowsDACLMatch{failure: windowsDACLUnexpectedEntry, index: index}
	}
	for _, found := range seen {
		if !found {
			return windowsDACLMatch{failure: windowsDACLMissingCanonical, index: -1, extras: extras}
		}
	}
	return windowsDACLMatch{failure: windowsDACLMatched, index: -1, extras: extras}
}
