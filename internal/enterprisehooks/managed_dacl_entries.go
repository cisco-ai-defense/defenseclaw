// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"strings"
)

// managedDACLEntry is one ACE of a managed Windows path's DACL, reduced to
// what the protection check compares. It is platform-neutral so the policy is
// testable everywhere; the Windows code fills it from GetAce.
type managedDACLEntry struct {
	SID   string
	Type  uint8
	Mask  uint32
	Flags uint8
}

const (
	managedDACLAccessAllowedType uint8 = 0 // ACCESS_ALLOWED_ACE_TYPE

	// managedDACLReadOnlyMask is every right an extra ACE may grant on a managed
	// path: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE (read data, read
	// attributes, read extended attributes, traverse/execute, READ_CONTROL,
	// SYNCHRONIZE) and their GENERIC_READ / GENERIC_EXECUTE forms. Write and
	// append data, write attributes, delete, delete child, WRITE_DAC,
	// WRITE_OWNER, GENERIC_WRITE and GENERIC_ALL are outside it.
	managedDACLReadOnlyMask uint32 = 0x001200a9 | 0x80000000 | 0x20000000
)

// managedDACLBroadPrincipals are well-known groups that cover every user,
// every logon of a kind, or every app container. An extra read grant to one of
// them is rejected even on a directory: an agent sandbox grants its own group,
// never these. Domain-relative groups are matched by RID in
// managedDACLBroadPrincipalName.
var managedDACLBroadPrincipals = map[string]string{
	"S-1-1-0":      "Everyone",
	"S-1-2-0":      "Local",
	"S-1-2-1":      "Console Logon",
	"S-1-5-2":      "Network",
	"S-1-5-4":      "Interactive",
	"S-1-5-7":      "Anonymous Logon",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-14":     "Remote Interactive Logon",
	"S-1-5-113":    "Local account",
	"S-1-5-32-545": "Users",
	"S-1-5-32-546": "Guests",
	"S-1-5-32-547": "Power Users",
	"S-1-5-32-555": "Remote Desktop Users",
	"S-1-15-2-1":   "ALL APPLICATION PACKAGES",
	"S-1-15-2-2":   "ALL RESTRICTED APPLICATION PACKAGES",
}

// managedDACLBroadDomainRIDs are the domain-relative RIDs of groups that cover
// every domain account: Domain Users (513) and Domain Guests (514), under any
// S-1-5-21-<domain> prefix.
var managedDACLBroadDomainRIDs = map[string]string{
	"513": "Domain Users",
	"514": "Domain Guests",
}

// managedDACLBroadPrincipalName names sid when it is a broad group, "" when it
// is not.
func managedDACLBroadPrincipalName(sid string) string {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	if name, ok := managedDACLBroadPrincipals[sid]; ok {
		return name
	}
	if strings.HasPrefix(sid, "S-1-5-21-") {
		parts := strings.Split(sid, "-")
		// S-1-5-21-<a>-<b>-<c>-<rid>: a domain group has exactly three
		// sub-authorities between 21 and the RID.
		if len(parts) == 8 {
			if name, ok := managedDACLBroadDomainRIDs[parts[7]]; ok {
				return name
			}
		}
	}
	return ""
}

// checkManagedDACLEntries holds a managed path's DACL to its canonical
// entries. Every canonical entry must be present exactly once. On a directory,
// an extra entry is accepted only when it is an allow entry granting read and
// execute rights alone to a principal other than a broad built-in group: agent
// sandboxes grant their own group read access to the folders their sandboxed
// processes run hooks from (Codex adds CodexSandboxUsers with (OI)(CI)(RX) to
// the hook runtime folder), and nothing such an entry allows can change the
// managed runtime. Files, which include the connector tokens, accept no extra
// entry at all. Any other extra entry (a write-capable grant, a deny, an audit
// or object ACE, a duplicate canonical entry) is rejected and named.
func checkManagedDACLEntries(path string, directory bool, expected, actual []managedDACLEntry) error {
	seen := make([]bool, len(expected))
	for index, entry := range actual {
		if entry.Type != managedDACLAccessAllowedType {
			return fmt.Errorf(
				"enterprise hooks: managed Windows DACL on %s contains non-canonical ACE type %d at index %d (principal %s)",
				path, entry.Type, index, entry.SID,
			)
		}
		match, duplicate := -1, false
		for candidate, want := range expected {
			if !strings.EqualFold(entry.SID, want.SID) || entry.Mask != want.Mask || entry.Flags != want.Flags {
				continue
			}
			if seen[candidate] {
				duplicate = true
				continue
			}
			match = candidate
			break
		}
		if match >= 0 {
			seen[match] = true
			continue
		}
		if duplicate {
			return fmt.Errorf(
				"enterprise hooks: managed Windows DACL on %s repeats the canonical ACE for principal %s (mask 0x%x, inheritance 0x%x)",
				path, entry.SID, entry.Mask, entry.Flags,
			)
		}
		if !directory {
			return fmt.Errorf(
				"enterprise hooks: managed Windows DACL on file %s has an extra ACE for principal %s (mask 0x%x, inheritance 0x%x); files accept only the canonical entries",
				path, entry.SID, entry.Mask, entry.Flags,
			)
		}
		if name := managedDACLBroadPrincipalName(entry.SID); name != "" {
			return fmt.Errorf(
				"enterprise hooks: managed Windows DACL on %s grants the broad group %s (%s) access (mask 0x%x, inheritance 0x%x)",
				path, name, entry.SID, entry.Mask, entry.Flags,
			)
		}
		if entry.Mask&^managedDACLReadOnlyMask != 0 {
			return fmt.Errorf(
				"enterprise hooks: managed Windows DACL on %s grants principal %s rights beyond read and execute (mask 0x%x, inheritance 0x%x)",
				path, entry.SID, entry.Mask, entry.Flags,
			)
		}
	}
	for candidate, want := range expected {
		if !seen[candidate] {
			return fmt.Errorf(
				"enterprise hooks: managed Windows DACL on %s is missing the canonical ACE for principal %s (mask 0x%x, inheritance 0x%x)",
				path, want.SID, want.Mask, want.Flags,
			)
		}
	}
	return nil
}
