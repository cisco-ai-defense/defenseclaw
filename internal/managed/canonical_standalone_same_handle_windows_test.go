//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// g582 review 6 S1 and review 5 L1: on standalone the repair itself makes the
// refusal decision on the handle it stamps, so nothing that changes between a
// caller's read-only check and the repair (an entry granted, a hard link
// removed, the object replaced) gets an untrusted object re-stamped in place.

const (
	sameHandleGateway = `NT SERVICE\EventLog`
	// Trusted-only drift: an extra BUILTIN\Users read entry.
	sameHandleTrustedDrift = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	// The same, plus a BUILTIN\Guests write entry.
	sameHandleGuestsWriter = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;FW;;;BG)"
	// Guests own the file.
	sameHandleGuestsOwner = "O:BGD:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

func setSameHandleDescriptor(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := RunWithWindowsRepairPrivileges(func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			owner, nil, dacl, nil)
	}); err != nil {
		t.Fatalf("stamp %s on %s: %v", sddl, path, err)
	}
}

func sameHandleFile(t *testing.T, dir, name, sddl string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	setSameHandleDescriptor(t, path, sddl)
	return path
}

func hasGuestsEntry(descriptor string) bool {
	return strings.Contains(descriptor, ";;;BG)") || strings.Contains(descriptor, "O:BG")
}

func TestStandaloneRepairJudgesTheObjectOnTheHandleItStamps(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	t.Setenv(TrustStrictAncestorsEnv, "")
	for _, tc := range []struct {
		name       string
		standalone bool
		between    func(t *testing.T, path string)
		want       CanonicalOutcome
		refused    bool
	}{
		{name: "trusted-only drift is repaired", standalone: true, want: CanonicalRepaired},
		{
			name: "a writer granted after the assessment is refused on the repair handle", standalone: true,
			between: func(t *testing.T, path string) { setSameHandleDescriptor(t, path, sameHandleGuestsWriter) },
			want:    CanonicalBoundary, refused: true,
		},
		{
			name: "an owner given away after the assessment is refused on the repair handle", standalone: true,
			between: func(t *testing.T, path string) { setSameHandleDescriptor(t, path, sameHandleGuestsOwner) },
			want:    CanonicalBoundary, refused: true,
		},
		{
			name:    "Secure Client keeps the base repair of a writer granted in between",
			between: func(t *testing.T, path string) { setSameHandleDescriptor(t, path, sameHandleGuestsWriter) },
			want:    CanonicalRepaired,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinTrustProfileForTest(t, tc.standalone)
			path := sameHandleFile(t, t.TempDir(), "record.json", sameHandleTrustedDrift)
			previous := canonicalBeforeStamp
			t.Cleanup(func() { canonicalBeforeStamp = previous })
			var stamped string
			canonicalBeforeStamp = func(target string) {
				if tc.between != nil && strings.EqualFold(target, path) {
					tc.between(t, path)
					stamped = privilegedDescriptorForTest(t, path)
				}
			}

			result, err := EnsureCanonical(path, ObjectAdminFile, CanonicalOptions{Quiet: true, AllowUntrustedOwnerTransfer: true})

			canonicalBeforeStamp = previous
			if err != nil {
				t.Fatal(err)
			}
			if result.Outcome != tc.want {
				t.Fatalf("outcome = %+v, want %s", result, tc.want)
			}
			after := privilegedDescriptorForTest(t, path)
			if tc.refused {
				if result.RepairError != standaloneInPlaceRepairRefused(result) {
					t.Fatalf("repair error = %q, want the standalone refusal", result.RepairError)
				}
				if after != stamped {
					t.Fatalf("the refused repair changed the descriptor: %s -> %s", stamped, after)
				}
				return
			}
			if hasGuestsEntry(after) {
				t.Fatalf("descriptor after repair = %s, want the canonical one", after)
			}
		})
	}
}

// An object replaced between the assessment and the repair is never stamped:
// the repair handle is not the object that was judged.
func TestStandaloneRepairNeverStampsAnObjectReplacedAfterTheAssessment(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	t.Setenv(TrustStrictAncestorsEnv, "")
	pinTrustProfileForTest(t, true)
	dir := t.TempDir()
	path := sameHandleFile(t, dir, "record.json", sameHandleTrustedDrift)
	previous := canonicalBeforeStamp
	t.Cleanup(func() { canonicalBeforeStamp = previous })
	var replaced string
	canonicalBeforeStamp = func(target string) {
		if !strings.EqualFold(target, path) {
			return
		}
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatalf("move the judged object aside: %v", err)
		}
		if err := os.WriteFile(path, []byte("y"), 0o600); err != nil {
			t.Fatal(err)
		}
		setSameHandleDescriptor(t, path, sameHandleGuestsWriter)
		replaced = privilegedDescriptorForTest(t, path)
	}

	result, err := EnsureCanonical(path, ObjectAdminFile, CanonicalOptions{Quiet: true})

	canonicalBeforeStamp = previous
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome == CanonicalRepaired || result.Outcome == CanonicalOK {
		t.Fatalf("outcome = %+v, want the replaced object left unrepaired", result)
	}
	if after := privilegedDescriptorForTest(t, path); after != replaced {
		t.Fatalf("the replacement was stamped: %s -> %s", replaced, after)
	}
}

// AllowUntrustedOwnerTransfer does not let a standalone repair adopt an
// untrusted owner or strip an untrusted writer in place, so an object that
// was missing at a caller's check and appears before the repair is refused.
func TestStandaloneRepairRefusesUntrustedObjectsWhateverOwnerTransferSays(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	t.Setenv(TrustStrictAncestorsEnv, "")
	for _, tc := range []struct {
		name       string
		sddl       string
		standalone bool
		want       CanonicalOutcome
	}{
		{name: "standalone, untrusted writer", sddl: sameHandleGuestsWriter, standalone: true, want: CanonicalBoundary},
		{name: "standalone, untrusted owner", sddl: sameHandleGuestsOwner, standalone: true, want: CanonicalBoundary},
		{name: "Secure Client, untrusted owner with the transfer", sddl: sameHandleGuestsOwner, want: CanonicalRepaired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinTrustProfileForTest(t, tc.standalone)
			path := sameHandleFile(t, t.TempDir(), "record.json", tc.sddl)
			before := privilegedDescriptorForTest(t, path)
			result, err := EnsureCanonical(path, ObjectAdminFile, CanonicalOptions{Quiet: true, AllowUntrustedOwnerTransfer: true})
			if err != nil {
				t.Fatal(err)
			}
			if result.Outcome != tc.want {
				t.Fatalf("outcome = %+v, want %s", result, tc.want)
			}
			after := privilegedDescriptorForTest(t, path)
			if tc.want == CanonicalBoundary && after != before {
				t.Fatalf("the refused repair changed the descriptor: %s -> %s", before, after)
			}
			if tc.want == CanonicalRepaired && hasGuestsEntry(after) {
				t.Fatalf("descriptor after repair = %s, want the canonical one", after)
			}
		})
	}
}

// The gateway data-path repair: a writer granted between the decider's
// read-only check and the repair, and a hard link that is there at the check
// and gone before the repair, never end in an in-place re-stamp.
func TestStandaloneDataPathRepairIsNotRacedPastItsCheck(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	t.Setenv(TrustStrictAncestorsEnv, "")
	for _, tc := range []struct {
		name       string
		standalone bool
		sddl       string
		link       bool
		between    func(t *testing.T, path string)
		wantRepair bool
	}{
		{
			name: "writer granted after the check", standalone: true, sddl: sameHandleTrustedDrift,
			between: func(t *testing.T, path string) { setSameHandleDescriptor(t, path, sameHandleGuestsWriter) },
		},
		{
			name: "hard link at the check, removed before the repair", standalone: true, sddl: sameHandleGuestsWriter, link: true,
			between: func(t *testing.T, path string) { _ = os.Remove(path + ".link") },
		},
		{
			name: "Secure Client keeps the base repair", sddl: sameHandleTrustedDrift, wantRepair: true,
			between: func(t *testing.T, path string) { setSameHandleDescriptor(t, path, sameHandleGuestsWriter) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinTrustProfileForTest(t, tc.standalone)
			dir := t.TempDir()
			path := sameHandleFile(t, dir, "audit.db", tc.sddl)
			if tc.link {
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatalf("hard link: %v", err)
				}
			}
			previous := standaloneRepairAfterCheck
			t.Cleanup(func() { standaloneRepairAfterCheck = previous })
			var stamped string
			standaloneRepairAfterCheck = func(target string) {
				if strings.EqualFold(target, path) && tc.between != nil {
					tc.between(t, path)
					stamped = privilegedDescriptorForTest(t, path)
				}
			}
			if stamped == "" {
				stamped = privilegedDescriptorForTest(t, path)
			}

			results := RepairWindowsManagedDataPaths(
				ManagedDataPaths{AuditDBPath: path},
				CanonicalOptions{Quiet: true, GatewayServiceAccount: sameHandleGateway, AllowUntrustedOwnerTransfer: true},
			)

			standaloneRepairAfterCheck = previous
			var got *CanonicalResult
			for index := range results {
				if strings.EqualFold(results[index].Path, path) {
					got = &results[index]
				}
			}
			if got == nil {
				t.Fatalf("no result for %s in %+v", path, results)
			}
			after := privilegedDescriptorForTest(t, path)
			if tc.wantRepair {
				if got.Outcome != CanonicalRepaired || hasGuestsEntry(after) {
					t.Fatalf("result %+v, descriptor %s: want the base repair", *got, after)
				}
				return
			}
			if got.Outcome == CanonicalRepaired || got.Outcome == CanonicalOK {
				t.Fatalf("result %+v: want a refusal", *got)
			}
			if !hasGuestsEntry(after) {
				t.Fatalf("the untrusted writer was stripped in place: %s (was %s)", after, stamped)
			}
		})
	}
}

// StampStandaloneTrustedObject (the hook guardian folder and secrets folder
// stamps) judges the folder on the handle it writes.
func TestStampStandaloneTrustedObjectJudgesOnTheHandleItWrites(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	t.Setenv(TrustStrictAncestorsEnv, "")
	const folderTrustedDrift = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)"
	const folderGuestsWriter = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;BG)"
	const canonical = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	for _, tc := range []struct {
		name    string
		sddl    string
		between string
		refused bool
	}{
		{name: "trusted-only drift is stamped", sddl: folderTrustedDrift},
		{name: "an untrusted writer is refused", sddl: folderGuestsWriter, refused: true},
		{name: "a writer granted after the caller's check is refused", sddl: folderTrustedDrift, between: folderGuestsWriter, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "folder")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			setSameHandleDescriptor(t, path, tc.sddl)
			previous := canonicalBeforeStamp
			t.Cleanup(func() { canonicalBeforeStamp = previous })
			canonicalBeforeStamp = func(target string) {
				if tc.between != "" && strings.EqualFold(target, path) {
					setSameHandleDescriptor(t, path, tc.between)
				}
			}
			before := ""
			if tc.between == "" {
				before = privilegedDescriptorForTest(t, path)
			}

			err := StampStandaloneTrustedObject(path, ObjectAdminDirectory, canonical)

			canonicalBeforeStamp = previous
			after := privilegedDescriptorForTest(t, path)
			if !tc.refused {
				if err != nil || hasGuestsEntry(after) || strings.Contains(after, ";;;BU)") {
					t.Fatalf("stamp = %v, descriptor %s: want the canonical descriptor", err, after)
				}
				return
			}
			var refused *StandaloneContentDriftError
			if !errors.As(err, &refused) || !strings.Contains(err.Error(), path) {
				t.Fatalf("stamp = %v, want a StandaloneContentDriftError naming %s", err, path)
			}
			if !hasGuestsEntry(after) || (before != "" && after != before) {
				t.Fatalf("the refused stamp changed the descriptor: %s -> %s", before, after)
			}
		})
	}
}
