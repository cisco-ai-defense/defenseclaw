//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// g582 review 4 F2: the standalone "DefenseClaw manages this folder" test
// counted only five marker names that sat in the folder itself. An account
// that could delete children deleted the marker and the folder was then taken
// over in place; the hook runtime folder's files were never on the list; and a
// marker a user planted in a folder they pre-created blocked the documented
// pre-install takeover. The decision is now one function: an
// administrator-only record outside the folder decides first, and only a
// marker owned by SYSTEM, Administrators or TrustedInstaller counts.

// f2Ledger points the hook guardian ledger at a fresh administrator-only
// file naming targets (none for an empty list).
func f2Ledger(t *testing.T, targets ...string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "hook-guardian-state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, dir)
	if len(targets) == 0 {
		return
	}
	data, err := json.Marshal(map[string]any{
		"version": 1,
		"protected_targets": []any{map[string]any{
			"connector": "claudecode",
			"result":    map[string]any{"hook_config_paths": targets},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(dir, managed.HookGuardianAuthorizationFile)
	if err := os.WriteFile(ledger, data, 0o600); err != nil {
		t.Fatal(err)
	}
	stampGAP633SDDL(t, ledger, gap633NoUsersReadFile)
}

func f2UsersModifyFolder(t *testing.T, name string) string {
	t.Helper()
	folder := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	stampGAP633SDDL(t, folder, gap633UsersModifyFolder)
	return folder
}

func TestStandalonePolicyFolderTakeoverDecidesFromTheRecordAndTrustedMarkers(t *testing.T) {
	requireGAP633Elevated(t)
	for _, tc := range []struct {
		name string
		// recorded: the ledger names the policy file in the folder.
		recorded bool
		// marker: "" none (deleted or never written), "trusted" owned by
		// Administrators, "planted" owned by BUILTIN\Users.
		marker  string
		refused bool
	}{
		{name: "the marker was deleted, the ledger still names the folder", recorded: true, refused: true},
		{name: "a planted, Users-owned marker is ignored", marker: "planted"},
		{name: "an Administrators-owned marker counts", marker: "trusted", refused: true},
		{name: "twin: no record, no marker (created before the first install)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setGAP633Profile(t, true, nil)
			folder := f2UsersModifyFolder(t, "managed-settings.d")
			if tc.recorded {
				f2Ledger(t, filepath.Join(folder, "90-defenseclaw.json"))
			} else {
				f2Ledger(t)
			}
			if tc.marker != "" {
				marker := filepath.Join(folder, windowsClaudeManagedStateFile)
				if err := os.WriteFile(marker, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
				sddl := gap633CanonicalFile
				if tc.marker == "planted" {
					sddl = gap633UsersOwnerFile
				}
				stampGAP633SDDL(t, marker, sddl)
			}
			before := gap633Descriptor(t, folder)

			err := repairWindowsManagedPolicyFolder(folder, validateWindowsManagedPolicyDirectoryDescriptor)

			after := gap633Descriptor(t, folder)
			var refused *managed.StandaloneContentDriftError
			if tc.refused {
				if !errors.As(err, &refused) {
					t.Fatalf("err = %v, want a standalone refusal", err)
				}
				if after != before {
					t.Fatalf("the managed folder was taken over in place: %s -> %s", before, after)
				}
				return
			}
			if err != nil || errors.As(err, &refused) {
				t.Fatalf("err = %v, want the pre-install takeover", err)
			}
			if gap633UsersCanWrite(after) {
				t.Fatalf("the folder was not taken over: %s", after)
			}
		})
	}
}

func TestStandaloneHookClosureRefusesAnUntrustedHookRuntimeFolder(t *testing.T) {
	requireGAP633Elevated(t)
	setGAP633Profile(t, true, nil)
	f2Ledger(t)
	runtimeDir := f2UsersModifyFolder(t, managed.StandaloneWindowsHookRuntimeDirName)
	summary := filepath.Join(runtimeDir, "machine-policy.json")
	if err := os.WriteFile(summary, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	stampGAP633SDDL(t, summary, gap633CanonicalFile)
	before := gap633Descriptor(t, runtimeDir)

	err := CloseWindowsStandaloneHooksForUnprovenUndo(managed.StandaloneLayout{HookRuntimeDir: runtimeDir})

	if after := gap633Descriptor(t, runtimeDir); after != before {
		t.Fatalf("the hook runtime folder was taken over in place: %s -> %s (err %v)", before, after, err)
	}
	var refused *managed.StandaloneContentDriftError
	if !errors.As(err, &refused) {
		t.Fatalf("err = %v, want a standalone refusal", err)
	}
	if _, statErr := os.Lstat(windowsStandaloneHookClosurePath(managed.StandaloneLayout{HookRuntimeDir: runtimeDir})); statErr == nil {
		t.Fatal("the closure was published into the refused folder")
	}
}
