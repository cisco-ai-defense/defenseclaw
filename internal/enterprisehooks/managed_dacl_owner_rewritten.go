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
// DefenseClaw never writes that shape itself; every release from 1.0.2 on
// creates the file with the OWNER RIGHTS entry and the same three others.
// But an immutable managed runtime generation bundle is never rewritten,
// so the guardian never puts the entry back, and refusing it made the
// generation collection of every later upgrade, uninstall and reinstall
// fail with 1603 (rel-1-0-6:GAP-0303). Only these two exact shapes are
// accepted, for a file the account owns: one more, one less or one changed
// entry is refused as before.
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

// windowsManagedFileOwnerRewrittenExpected is the canonical managed file
// DACL of target without its OWNER RIGHTS entry, as Windows stores it.
func windowsManagedFileOwnerRewrittenExpected(target string) []windowsDACLExpectedEntry {
	return []windowsDACLExpectedEntry{
		{sid: windowsSIDLocalSystem, mask: windowsACEFileAllAccess},
		{sid: windowsSIDAdministrators, mask: windowsACEFileAllAccess},
		{sid: strings.TrimSpace(target), mask: windowsACEManagedUserFileAccess},
	}
}

// windowsManagedFileOwnerRewrittenDACL reports whether entries are exactly
// the canonical managed file DACL of target after an owner write: its three
// explicit access-allowed entries with no inheritance flags, in any order,
// and either no OWNER RIGHTS entry or that entry made inherit-only, and
// nothing else.
func windowsManagedFileOwnerRewrittenDACL(entries []windowsDACLEntry, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" || strings.EqualFold(target, windowsSIDLocalSystem) ||
		strings.EqualFold(target, windowsSIDAdministrators) ||
		strings.EqualFold(target, windowsSIDOwnerRights) {
		return false
	}
	expected := windowsManagedFileOwnerRewrittenExpected(target)
	if len(entries) == len(expected)+1 {
		expected = append(expected, windowsDACLExpectedEntry{
			sid:   windowsSIDOwnerRights,
			mask:  windowsACEReadControlOnly,
			flags: windowsACEInheritOnly,
		})
	}
	return matchWindowsCanonicalDACL(entries, expected, target, false).failure == windowsDACLMatched
}
