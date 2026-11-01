// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "testing"

const ownerRewrittenTestTarget = "S-1-5-21-2566694559-2372738039-4094494201-1115"

func ownerRewrittenTestEntries() []windowsDACLEntry {
	// The order Windows stores after an owner write: SYSTEM, Administrators,
	// the account (rel-1-0-6:GAP-0303, icacls of the 1.0.6 generation files).
	return []windowsDACLEntry{
		{aceType: windowsACEAccessAllowedType, mask: windowsACEFileAllAccess, sid: windowsSIDLocalSystem},
		{aceType: windowsACEAccessAllowedType, mask: windowsACEFileAllAccess, sid: windowsSIDAdministrators},
		{aceType: windowsACEAccessAllowedType, mask: windowsACEManagedUserFileAccess, sid: ownerRewrittenTestTarget},
	}
}

func TestWindowsManagedFileOwnerRewrittenDACLAcceptsExactlyTheOldShape(t *testing.T) {
	entries := ownerRewrittenTestEntries()
	if !windowsManagedFileOwnerRewrittenDACL(entries, ownerRewrittenTestTarget) {
		t.Fatal("the canonical file DACL without its OWNER RIGHTS entry was refused")
	}
	// Any order: the account first, as the writer lists it.
	reordered := []windowsDACLEntry{entries[2], entries[0], entries[1]}
	if !windowsManagedFileOwnerRewrittenDACL(reordered, ownerRewrittenTestTarget) {
		t.Fatal("the same three entries in another order were refused")
	}
	// A raw owner write leaves the OWNER RIGHTS entry inherit-only.
	inheritOnly := append(append([]windowsDACLEntry(nil), entries...), windowsDACLEntry{
		aceType: windowsACEAccessAllowedType, flags: 0x08, mask: 0x00020000, sid: windowsSIDOwnerRights,
	})
	if !windowsManagedFileOwnerRewrittenDACL(inheritOnly, ownerRewrittenTestTarget) {
		t.Fatal("the canonical file DACL with an inherit-only OWNER RIGHTS entry was refused")
	}
	if windowsACEManagedUserFileAccess != 0x00120089|0x00120116|0x001200a0|0x00010000 {
		t.Fatalf("account mask 0x%08x is not FILE_GENERIC_READ|WRITE|EXECUTE|DELETE", windowsACEManagedUserFileAccess)
	}
}

func TestWindowsManagedFileOwnerRewrittenDACLRefusesAnythingLooser(t *testing.T) {
	const foreign = "S-1-5-21-2566694559-2372738039-4094494201-1116"
	base := ownerRewrittenTestEntries()
	with := func(edit func([]windowsDACLEntry) []windowsDACLEntry) []windowsDACLEntry {
		copied := append([]windowsDACLEntry(nil), base...)
		return edit(copied)
	}
	cases := map[string][]windowsDACLEntry{
		"foreign account write ACE added": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			return append(e, windowsDACLEntry{aceType: windowsACEAccessAllowedType, mask: windowsACEManagedUserFileAccess, sid: foreign})
		}),
		"foreign read-only ACE added": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			return append(e, windowsDACLEntry{aceType: windowsACEAccessAllowedType, mask: 0x001200a9, sid: foreign})
		}),
		"Users read ACE added": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			return append(e, windowsDACLEntry{aceType: windowsACEAccessAllowedType, mask: 0x001200a9, sid: "S-1-5-32-545"})
		}),
		"Everyone replaces Administrators": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			e[1].sid = "S-1-1-0"
			return e
		}),
		"foreign account replaces the account": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			e[2].sid = foreign
			return e
		}),
		"account holds full control": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			e[2].mask = windowsACEFileAllAccess
			return e
		}),
		"account holds WRITE_DAC": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			e[2].mask |= 0x00040000
			return e
		}),
		"account holds generic all": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			e[2].mask = 0x10000000
			return e
		}),
		"SYSTEM missing": with(func(e []windowsDACLEntry) []windowsDACLEntry { return e[1:] }),
		"Administrators missing": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			return []windowsDACLEntry{e[0], e[2]}
		}),
		"account missing":      with(func(e []windowsDACLEntry) []windowsDACLEntry { return e[:2] }),
		"SYSTEM entry doubled": with(func(e []windowsDACLEntry) []windowsDACLEntry { return []windowsDACLEntry{e[0], e[0], e[2]} }),
		"account entry inherited": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			e[2].flags = 0x10 // INHERITED_ACE
			return e
		}),
		"SYSTEM entry inheritable": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			e[0].flags = 0x03 // OBJECT_INHERIT | CONTAINER_INHERIT
			return e
		}),
		"deny entry for the account": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			return append(e, windowsDACLEntry{aceType: 0x01, mask: 0x00010000, sid: ownerRewrittenTestTarget})
		}),
		"account entry is a deny": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			e[2].aceType = 0x01
			return e
		}),
		"empty": nil,
		"inherit-only OWNER RIGHTS with more rights": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			return append(e, windowsDACLEntry{aceType: windowsACEAccessAllowedType, flags: 0x08, mask: 0x00060000, sid: windowsSIDOwnerRights})
		}),
		"inheritable OWNER RIGHTS entry": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			return append(e, windowsDACLEntry{aceType: windowsACEAccessAllowedType, flags: 0x0b, mask: 0x00020000, sid: windowsSIDOwnerRights})
		}),
		"inherit-only foreign entry": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			return append(e, windowsDACLEntry{aceType: windowsACEAccessAllowedType, flags: 0x08, mask: 0x00020000, sid: foreign})
		}),
		"two inherit-only OWNER RIGHTS entries": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			ow := windowsDACLEntry{aceType: windowsACEAccessAllowedType, flags: 0x08, mask: 0x00020000, sid: windowsSIDOwnerRights}
			return append(e, ow, ow)
		}),
		"inherit-only OWNER RIGHTS but Administrators missing": with(func(e []windowsDACLEntry) []windowsDACLEntry {
			return []windowsDACLEntry{e[0], e[2], {aceType: windowsACEAccessAllowedType, flags: 0x08, mask: 0x00020000, sid: windowsSIDOwnerRights}}
		}),
	}
	for name, entries := range cases {
		if windowsManagedFileOwnerRewrittenDACL(entries, ownerRewrittenTestTarget) {
			t.Errorf("%s: accepted, want refused", name)
		}
	}
	// The canonical DACL itself is another shape (the strict check takes it).
	canonical := append([]windowsDACLEntry{{aceType: windowsACEAccessAllowedType, mask: 0x00020000, sid: windowsSIDOwnerRights}}, base...)
	if windowsManagedFileOwnerRewrittenDACL(canonical, ownerRewrittenTestTarget) {
		t.Error("the four-entry canonical DACL matched the owner-rewritten shape")
	}
	// The target itself must be a real account.
	for _, target := range []string{"", " ", windowsSIDLocalSystem, windowsSIDAdministrators, windowsSIDOwnerRights} {
		if windowsManagedFileOwnerRewrittenDACL(base, target) {
			t.Errorf("target %q: accepted, want refused", target)
		}
	}
}
