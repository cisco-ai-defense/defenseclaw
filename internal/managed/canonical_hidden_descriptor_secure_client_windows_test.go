//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"testing"
)

// g582 review 5 M1: round 5 made the read-only assessment re-read a hidden
// descriptor with the repair privileges on every profile. On Secure Client a
// SYSTEM caller (the guardian or Setup validating the hook token file) then
// judged the real descriptor and refused what it used to accept, and a
// caller without the privileges logged a once-per-process "grant the
// privilege" prerequisite. Secure Client's assessment of a hidden descriptor
// is Accepted, as on the base, and it does not take the privileges.
//
// g582 review 6 M1: the same holds with the strict pin set, which any
// managed host may set to tighten trust. The base returns Boundary there
// ("security descriptor is not readable") without the privileges; round 6
// re-read the descriptor with them and could return Accepted instead.
func TestSecureClientHiddenDescriptorAssessmentIsUnchanged(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	for _, tc := range []struct {
		name      string
		directory bool
		sddl      string
		strict    bool
		want      CanonicalOutcome
	}{
		{name: "token-style file, Guests write, descriptor hidden", sddl: hiddenWriterFileSDDL, want: CanonicalAccepted},
		{name: "folder, Guests write, descriptor and listing hidden", directory: true, sddl: hiddenWriterFolderSDDL, want: CanonicalAccepted},
		{name: "strict pin, token-style file, descriptor hidden", sddl: hiddenWriterFileSDDL, strict: true, want: CanonicalBoundary},
		{name: "strict pin, folder, descriptor and listing hidden", directory: true, sddl: hiddenWriterFolderSDDL, strict: true, want: CanonicalBoundary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(TrustStrictAncestorsEnv, "")
			if tc.strict {
				t.Setenv(TrustStrictAncestorsEnv, "1")
				if !TrustStrictAncestors() {
					t.Fatal("the strict pin did not take")
				}
			}
			path := filepath.Join(t.TempDir(), "object")
			kind := ObjectAdminFile
			if tc.directory {
				kind = ObjectAdminDirectory
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			stampHiddenDescriptorForTest(t, path, tc.sddl)
			pinTrustProfileForTest(t, false)
			before := privilegedDescriptorForTest(t, path)
			privileged := 0
			previous := canonicalRunWithRepairPrivileges
			canonicalRunWithRepairPrivileges = func(fn func() error) error {
				privileged++
				return previous(fn)
			}
			t.Cleanup(func() { canonicalRunWithRepairPrivileges = previous })

			assessed, err := AssessCanonical(path, kind, CanonicalOptions{Quiet: true})

			canonicalRunWithRepairPrivileges = previous
			if err != nil {
				t.Fatal(err)
			}
			if assessed.Outcome != tc.want {
				t.Fatalf("Secure Client assessment = %+v, want %s as on the base", assessed, tc.want)
			}
			if tc.strict && assessed.RepairError != "security descriptor is not readable" {
				t.Fatalf("Secure Client strict assessment = %+v, want the base reason", assessed)
			}
			if privileged != 0 {
				t.Fatalf("the Secure Client assessment took the repair privileges %d time(s)", privileged)
			}
			if after := privilegedDescriptorForTest(t, path); after != before {
				t.Fatalf("the read-only assessment changed the descriptor: %s -> %s", before, after)
			}
		})
	}
}
