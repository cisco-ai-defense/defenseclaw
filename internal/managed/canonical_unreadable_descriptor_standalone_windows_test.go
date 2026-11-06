//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// g582 review 4 F1: when not even the repair privileges can read an object's
// descriptor, standalone judges it a boundary (never Accepted), so no
// standalone refusal lets it be re-stamped; Secure Client keeps the accepted
// verdict.
func TestStandaloneUnreadableDescriptorIsABoundary(t *testing.T) {
	for _, tc := range []struct {
		name       string
		standalone bool
		want       CanonicalOutcome
	}{
		{name: "standalone", standalone: true, want: CanonicalBoundary},
		{name: "twin: Secure Client", want: CanonicalAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(TrustStrictAncestorsEnv, "")
			path := filepath.Join(t.TempDir(), "object")
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			// The owner keeps WRITE_DAC through the OWNER RIGHTS entry, so
			// the fixture is given back without privileges.
			setTestFileDACL(t, path, testDACL(t, "D:P(A;;0x40080;;;OW)(A;;FA;;;BG)"), true)
			t.Cleanup(func() { setTestFileDACL(t, path, testDACL(t, canonicalTestDACL), true) })
			if handle, err := openCanonicalObject(path, uint32(windows.READ_CONTROL)); err == nil {
				_ = windows.CloseHandle(handle)
				t.Skip("this token still reads the descriptor")
			}
			previous := canonicalRunWithRepairPrivileges
			calls := 0
			canonicalRunWithRepairPrivileges = func(func() error) error {
				calls++
				return windows.ERROR_ACCESS_DENIED
			}
			t.Cleanup(func() { canonicalRunWithRepairPrivileges = previous })
			pinTrustProfileForTest(t, tc.standalone)

			assessed, err := AssessCanonical(path, ObjectAdminFile, CanonicalOptions{Quiet: true})
			if err != nil {
				t.Fatal(err)
			}
			if calls == 0 {
				t.Fatal("the assessment never tried the privileged read")
			}
			if assessed.Outcome != tc.want {
				t.Fatalf("outcome = %s, want %s (%+v)", assessed.Outcome, tc.want, assessed)
			}
			refusal := RefuseStandaloneInPlaceRepair(path, ObjectAdminFile)
			var refused *StandaloneContentDriftError
			if tc.standalone != errors.As(refusal, &refused) {
				t.Fatalf("RefuseStandaloneInPlaceRepair = %v, standalone %v", refusal, tc.standalone)
			}
		})
	}
}
