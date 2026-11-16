// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package winowner holds DefenseClaw's one Windows owner trust set for the
// folders and files it validates but did not create: a profile folder, the
// folder an agent made for its plugins, the folder that holds the Cowork
// removal marker. Windows picks their owner. A folder that a member of the
// Administrators group created (the built-in Administrator's profile among
// them) is owned by BUILTIN\Administrators, not by the user, whether or not
// the token was elevated (cowork-1-0-8 GAP-0085).
//
// The set is the account itself plus SystemOwnerSIDs, matched by well-known
// SID only. Users, Authenticated Users, Everyone and every other account are
// never trusted. cli/defenseclaw/file_permissions.py holds the same list as
// _WINDOWS_TRUSTED_SYSTEM_CONTROLLER_SIDS; a CLI test pins the two equal.
// Objects DefenseClaw creates itself are stamped with the user as owner and
// keep the stricter current-user rule (internal/safefile private files).
//
// The package uses only the standard library, so the small hook guard
// (internal/hookguard) can use it.
package winowner

// SystemOwnerSIDs are the Windows principals trusted as the owner of a folder
// or file, besides the account itself.
var SystemOwnerSIDs = [...]string{
	"S-1-5-18",     // LocalSystem
	"S-1-5-32-544", // BUILTIN\Administrators
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // NT SERVICE\TrustedInstaller
}

// OwnerRightsSID is OWNER RIGHTS. An ACE for it gives rights to the object's
// owner, which the owner check limits to the trust set.
const OwnerRightsSID = "S-1-3-4"

// CreatorOwnerSID is CREATOR OWNER. An inherit-only ACE for it gives the
// creator of a child object rights on that child only.
const CreatorOwnerSID = "S-1-3-0"

// CustodyWriteMask holds every right that lets a principal change a folder's
// entries or a file's content, DACL or owner: GENERIC_ALL, GENERIC_WRITE,
// DELETE, WRITE_DAC, WRITE_OWNER, FILE_ADD_FILE (FILE_WRITE_DATA),
// FILE_ADD_SUBDIRECTORY (FILE_APPEND_DATA), FILE_WRITE_EA, FILE_DELETE_CHILD
// and FILE_WRITE_ATTRIBUTES. cli/defenseclaw/file_permissions.py holds the
// same value as _WINDOWS_CUSTODY_WRITE_MASK; a CLI test pins the two equal.
const CustodyWriteMask uint32 = 0x500D0156

// TrustedWriter reports whether sid may hold CustodyWriteMask rights on a
// folder or file whose owner is Trusted: a Trusted owner or OWNER RIGHTS.
func TrustedWriter(sid, current string) bool {
	return sid == OwnerRightsSID || Trusted(sid, current)
}

// Trusted reports whether owner, a SID string, is current (the account's
// own SID) or one of SystemOwnerSIDs. An empty owner is never trusted, and
// an empty current trusts only SystemOwnerSIDs.
func Trusted(owner, current string) bool {
	if owner == "" {
		return false
	}
	if current != "" && owner == current {
		return true
	}
	for _, sid := range SystemOwnerSIDs {
		if owner == sid {
			return true
		}
	}
	return false
}
