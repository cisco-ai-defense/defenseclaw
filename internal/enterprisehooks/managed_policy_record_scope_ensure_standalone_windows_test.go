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

// g582 review 6 S2: the per-connector runtime folder refusal of review 5 M2,
// through the production entry point ensureWindowsManagedPolicyDirectory
// (what updateWindowsPerUserManagedEnrollment calls), on both of its repair
// branches: the ancestor walk (the folder fails the ancestor check) and the
// existing-folder branch (it passes the ancestor check and fails the
// directory check).
func TestStandaloneHookRuntimeConnectorFolderIsRefusedThroughEnsureWindowsManagedPolicyDirectory(t *testing.T) {
	requireGAP633Elevated(t)
	for _, tc := range []struct {
		name           string
		standalone     bool
		record         bool
		ancestorPasses bool
		refused        bool
	}{
		{name: "ancestor-walk branch, admin-only deployment record", standalone: true, record: true, refused: true},
		{name: "existing-folder branch, admin-only deployment record", standalone: true, record: true, ancestorPasses: true, refused: true},
		{name: "twin: standalone, no deployment record", standalone: true},
		{name: "twin: Secure Client, deployment record", record: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setGAP633Profile(t, tc.standalone, nil)
			f2Ledger(t)
			previousDir, previousAncestor := windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck
			folderLeaf := windowsManagedPolicyLeafTrust(managed.ObjectInstallDirectory)
			windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck = folderLeaf, folderLeaf
			if tc.ancestorPasses {
				windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
			}
			t.Cleanup(func() {
				windowsManagedPolicyDirTrustCheck, windowsManagedPolicyAncestorTrustCheck = previousDir, previousAncestor
			})
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

			err := ensureWindowsManagedPolicyDirectory(folder)

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
			if err != nil {
				t.Fatalf("err = %v, want the takeover", err)
			}
			if gap633UsersCanWrite(after) {
				t.Fatalf("the folder was not taken over: %s", after)
			}
		})
	}
}
