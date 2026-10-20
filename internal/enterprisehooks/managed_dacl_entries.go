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

// checkManagedDACLEntries holds a managed path's DACL to its canonical
// entries. Every canonical entry must be present exactly once. An extra entry
// is accepted only when it is an allow entry granting read and execute rights
// alone: agent sandboxes grant their own group read access to the folders their
// sandboxed processes run hooks from (Codex adds CodexSandboxUsers with
// (OI)(CI)(RX) to the hook runtime folder), and nothing such an entry allows
// can change the managed runtime. Any other extra entry (a write-capable grant,
// a deny, an audit or object ACE) is rejected and named.
func checkManagedDACLEntries(path string, expected, actual []managedDACLEntry) error {
	seen := make([]bool, len(expected))
	for index, entry := range actual {
		if entry.Type != managedDACLAccessAllowedType {
			return fmt.Errorf(
				"enterprise hooks: managed Windows DACL on %s contains non-canonical ACE type %d at index %d (principal %s)",
				path, entry.Type, index, entry.SID,
			)
		}
		match := -1
		for candidate, want := range expected {
			if !seen[candidate] && strings.EqualFold(entry.SID, want.SID) &&
				entry.Mask == want.Mask && entry.Flags == want.Flags {
				match = candidate
				break
			}
		}
		if match >= 0 {
			seen[match] = true
			continue
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
