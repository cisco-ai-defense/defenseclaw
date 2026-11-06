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
func TestSecureClientHiddenDescriptorAssessmentIsUnchanged(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	for _, tc := range []struct {
		name      string
		directory bool
		sddl      string
	}{
		{name: "token-style file, Guests write, descriptor hidden", sddl: hiddenWriterFileSDDL},
		{name: "folder, Guests write, descriptor and listing hidden", directory: true, sddl: hiddenWriterFolderSDDL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(TrustStrictAncestorsEnv, "")
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
			if assessed.Outcome != CanonicalAccepted {
				t.Fatalf("Secure Client assessment = %+v, want Accepted as on the base", assessed)
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
