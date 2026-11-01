// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "strings"

// Windows takes the explicit OWNER RIGHTS ACE out of effect when an object's
// owner is written, even when the new owner is the same account: a raw
// SetSecurityInfo of the owner turns it into an inherit-only entry, and
// icacls /setowner, takeown and back, an icacls /setowner /T or a robocopy
// /COPYALL that reaches the file (icacls /T follows a directory link into the
// account's DefenseClaw folder) remove it. A managed per-user file then keeps
// the rest of its canonical protected DACL: LocalSystem and Administrators
// full control and the account's read, write, execute and delete.
//
// The same happens to the .defenseclaw folder of the account and to its
// hooks child.
//
// DefenseClaw never writes that shape itself; every release from 1.0.2 on
// writes these DACLs with the OWNER RIGHTS entry. A running guardian puts the
// entry back on the folders and on the files it rewrites, but an immutable
// managed runtime generation bundle is never rewritten, and nothing repairs
// anything once an uninstall stopped the services: refusing that shape made
// the generation collection of every later upgrade, uninstall and reinstall
// fail with 1603 and left the host half-uninstalled (rel-1-0-6:GAP-0303).
// Only these two exact shapes are accepted, for an object the account owns:
// one more, one less or one changed entry is refused as before.
const (
	windowsSIDOwnerRights    = "S-1-3-4"
	windowsSIDLocalSystem    = "S-1-5-18"
	windowsSIDAdministrators = "S-1-5-32-544"

	// windowsACEFileAllAccess is FILE_ALL_ACCESS, the stored form of
	// GENERIC_ALL on a file.
	windowsACEFileAllAccess uint32 = 0x001f01ff
	// windowsACEReadControlOnly is READ_CONTROL, the OWNER RIGHTS entry's
	// only right.
	windowsACEReadControlOnly uint32 = 0x00020000
	// windowsACEInheritOnly is INHERIT_ONLY_ACE: an entry that applies to no
	// object, the form an owner write leaves the OWNER RIGHTS entry in.
	windowsACEInheritOnly uint8 = 0x08

	// windowsACEManagedUserFileAccess is FILE_GENERIC_READ |
	// FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE, the stored form of
	// the account's canonical file entry (icacls "Modify, Synchronize").
	windowsACEManagedUserFileAccess uint32 = 0x001301bf
)

// windowsManagedFileCanonicalExpected is the canonical managed file DACL of
// target as Windows stores it, OWNER RIGHTS entry included.
func windowsManagedFileCanonicalExpected(target string) []windowsDACLExpectedEntry {
	return []windowsDACLExpectedEntry{
		{sid: windowsSIDOwnerRights, mask: windowsACEReadControlOnly},
		{sid: windowsSIDLocalSystem, mask: windowsACEFileAllAccess},
		{sid: windowsSIDAdministrators, mask: windowsACEFileAllAccess},
		{sid: strings.TrimSpace(target), mask: windowsACEManagedUserFileAccess},
	}
}

// windowsManagedFileOwnerRewrittenDACL reports whether entries are exactly
// the canonical managed file DACL of target after an owner write
// (windowsOwnerRewrittenDACL with the file entries and no read-only extras).
func windowsManagedFileOwnerRewrittenDACL(entries []windowsDACLEntry, target string) bool {
	return windowsOwnerRewrittenDACL(entries, windowsManagedFileCanonicalExpected(target), target, false)
}

// windowsOwnerRewrittenDACL reports whether entries are the canonical DACL
// canonical (OWNER RIGHTS entry included, as Windows stores it) after an
// owner write: the explicit OWNER RIGHTS entry removed or made inherit-only,
// every other canonical entry exactly once, in any order, the read-only
// extra grants the strict check tolerates when tolerateReadOnly says so, and
// nothing else. A canonical set without its plain OWNER RIGHTS entry, and a
// target that is not an account, never match.
func windowsOwnerRewrittenDACL(
	entries []windowsDACLEntry,
	canonical []windowsDACLExpectedEntry,
	target string,
	tolerateReadOnly bool,
) bool {
	target = strings.TrimSpace(target)
	if target == "" || strings.EqualFold(target, windowsSIDLocalSystem) ||
		strings.EqualFold(target, windowsSIDAdministrators) ||
		strings.EqualFold(target, windowsSIDOwnerRights) {
		return false
	}
	stripped := make([]windowsDACLExpectedEntry, 0, len(canonical)+1)
	found := false
	for _, want := range canonical {
		if !found && strings.EqualFold(want.sid, windowsSIDOwnerRights) &&
			want.mask == windowsACEReadControlOnly && want.flags == 0 {
			found = true
			continue
		}
		stripped = append(stripped, want)
	}
	if !found {
		return false
	}
	if matchWindowsCanonicalDACL(entries, stripped, target, tolerateReadOnly).failure == windowsDACLMatched {
		return true
	}
	inheritOnly := append(stripped, windowsDACLExpectedEntry{
		sid:   windowsSIDOwnerRights,
		mask:  windowsACEReadControlOnly,
		flags: windowsACEInheritOnly,
	})
	return matchWindowsCanonicalDACL(entries, inheritOnly, target, tolerateReadOnly).failure == windowsDACLMatched
}
