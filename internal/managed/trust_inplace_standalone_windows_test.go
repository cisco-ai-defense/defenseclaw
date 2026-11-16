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
)

// g582 round 4 (class audit E2-E6): every in-place owner or DACL repair of a
// managed object outside RepairWindowsManagedInstall asks
// RefuseStandaloneInPlaceRepair first, and the guardian's data-path repair
// refuses an untrusted data_dir like the install layout does. Trusted-only
// drift and Secure Client keep the repair.

func TestRefuseStandaloneInPlaceRepairDecision(t *testing.T) {
	for _, tc := range []struct {
		name       string
		directory  bool
		dacl       string
		standalone bool
		refused    bool
	}{
		{name: "file, Users write", dacl: usersWriteDACL, standalone: true, refused: true},
		{name: "folder, Users write", directory: true, dacl: usersWriteDACL, standalone: true, refused: true},
		{name: "twin: file, an extra Users read", dacl: extraReaderDACL, standalone: true},
		{name: "twin: Secure Client, Users write", dacl: usersWriteDACL},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			setTestFileDACL(t, path, testDACL(t, tc.dacl), true)
			pinTrustProfileForTest(t, tc.standalone)
			err := RefuseStandaloneInPlaceRepair(path, kind)
			if !tc.refused {
				if err != nil {
					t.Fatalf("refused a repairable object: %v", err)
				}
				return
			}
			var refused *StandaloneContentDriftError
			want := "check it,"
			if tc.directory {
				want = "check what is in it"
			}
			if !errors.As(err, &refused) || !strings.Contains(err.Error(), path) ||
				!strings.Contains(err.Error(), "/remove:g") || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want a standalone refusal naming %s and the way out", err, path)
			}
		})
	}
}

func TestStandaloneManagedDataPathsRepairRefusesAnUntrustedDataDir(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dacl       string
		standalone bool
		refused    bool
	}{
		{name: "standalone, Users write on data_dir", dacl: usersWriteDACL, standalone: true, refused: true},
		{name: "twin: Secure Client, Users write on data_dir", dacl: usersWriteDACL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "runtime")
			if err := os.Mkdir(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			setTestFileDACL(t, dataDir, testDACL(t, tc.dacl), true)
			pinTrustProfileForTest(t, tc.standalone)
			results := RepairWindowsManagedDataPaths(ManagedDataPaths{DataDir: dataDir}, CanonicalOptions{Quiet: true})
			result, ok := installResultFor(results, dataDir)
			if !ok {
				t.Fatalf("no result for %s in %+v", dataDir, results)
			}
			assessed, err := AssessCanonical(dataDir, result.Kind, CanonicalOptions{Quiet: true})
			if err != nil {
				t.Fatal(err)
			}
			if tc.refused {
				if result.Outcome != CanonicalBoundary || !strings.Contains(result.RepairError, "/remove:g") {
					t.Fatalf("result = %+v, want a boundary refusal naming the way out", result)
				}
				if assessed.Outcome != CanonicalBoundary {
					t.Fatalf("the untrusted data_dir was re-stamped in place: %+v", assessed)
				}
				return
			}
			if result.Outcome != CanonicalRepaired {
				t.Skipf("this process cannot re-stamp the data_dir here (result %+v)", result)
			}
			if assessed.Outcome == CanonicalBoundary {
				t.Fatalf("the data_dir is still untrusted after the repair: %+v", assessed)
			}
		})
	}
}
