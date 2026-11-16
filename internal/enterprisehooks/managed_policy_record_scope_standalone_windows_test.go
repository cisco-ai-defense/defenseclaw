//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// g582 review 5 M2: a per-connector enrollment folder under
// DefenseClaw-HookRuntime that a user made writable, and whose enrollment.json
// and lock they deleted (or where no user is enrolled), was taken over in
// place by the folder repair updateWindowsPerUserManagedEnrollment reaches
// through ensureWindowsManagedPolicyDirectory. With an admin-only Setup
// deployment record it is refused and left as found.
func TestStandaloneHookRuntimeConnectorFolderWithDeletedMarkersIsRefused(t *testing.T) {
	requireGAP633Elevated(t)
	for _, tc := range []struct {
		name       string
		standalone bool
		record     bool
		refused    bool
	}{
		{name: "standalone, admin-only deployment record, enrollment and lock deleted", standalone: true, record: true, refused: true},
		{name: "twin: standalone, no deployment record (before the first install)", standalone: true},
		{name: "twin: Secure Client, deployment record", record: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setGAP633Profile(t, tc.standalone, nil)
			f2Ledger(t)
			base := t.TempDir()
			layout := managed.StandaloneLayout{
				HookRuntimeDir: filepath.Join(base, "Cisco", managed.StandaloneWindowsHookRuntimeDirName),
				LifecycleDir:   filepath.Join(base, "Cisco", "DefenseClaw", "install"),
			}
			for _, dir := range []string{layout.HookRuntimeDir, layout.LifecycleDir} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.record {
				record := filepath.Join(layout.LifecycleDir, "deployment.json")
				if err := os.WriteFile(record, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
				stampGAP633SDDL(t, record, gap633NoUsersReadFile)
			}
			t.Cleanup(managed.OverrideWindowsManagedFolderLayoutForTest(layout))
			folder := filepath.Join(layout.HookRuntimeDir, "copilot")
			if err := os.Mkdir(folder, 0o700); err != nil {
				t.Fatal(err)
			}
			stampGAP633SDDL(t, folder, gap633UsersModifyFolder)
			before := gap633Descriptor(t, folder)

			err := repairWindowsManagedPolicyFolder(folder, validateWindowsManagedPolicyDirectoryDescriptor)

			after := gap633Descriptor(t, folder)
			var refused *managed.StandaloneContentDriftError
			if tc.refused {
				if !errors.As(err, &refused) {
					t.Fatalf("err = %v, want a standalone refusal", err)
				}
				if after != before {
					t.Fatalf("the per-connector runtime folder was taken over in place: %s -> %s", before, after)
				}
				return
			}
			if err != nil || errors.As(err, &refused) {
				t.Fatalf("err = %v, want the takeover", err)
			}
			if gap633UsersCanWrite(after) {
				t.Fatalf("the folder was not taken over: %s", after)
			}
		})
	}
}

// g582 review 5 S1: a Users-writable vendor folder above a recorded policy
// folder (C:\Program Files\ClaudeCode above managed-settings.d) was taken over
// in place after the policy folder was renamed away, because the ledger's
// policy file is a grandchild. It is refused now; with no record it is still
// adopted.
func TestStandaloneVendorFolderAboveARemovedRecordedPolicyFolderIsRefused(t *testing.T) {
	requireGAP633Elevated(t)
	for _, tc := range []struct {
		name     string
		recorded bool
		refused  bool
	}{
		{name: "the ledger names vendor\\managed-settings.d\\90-defenseclaw.json, the policy folder was renamed away", recorded: true, refused: true},
		{name: "twin: no record (created before the first install)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setGAP633Profile(t, true, nil)
			vendor := f2UsersModifyFolder(t, "ClaudeCode")
			if tc.recorded {
				f2Ledger(t, filepath.Join(vendor, "managed-settings.d", "90-defenseclaw.json"))
			} else {
				f2Ledger(t)
			}
			before := gap633Descriptor(t, vendor)

			err := repairWindowsManagedPolicyFolder(vendor, validateWindowsManagedPolicyDirectoryDescriptor)

			after := gap633Descriptor(t, vendor)
			var refused *managed.StandaloneContentDriftError
			if tc.refused {
				if !errors.As(err, &refused) {
					t.Fatalf("err = %v, want a standalone refusal", err)
				}
				if after != before {
					t.Fatalf("the vendor folder was taken over in place: %s -> %s", before, after)
				}
				return
			}
			if err != nil || errors.As(err, &refused) {
				t.Fatalf("err = %v, want the pre-install takeover", err)
			}
			if gap633UsersCanWrite(after) {
				t.Fatalf("the vendor folder was not taken over: %s", after)
			}
		})
	}
}
