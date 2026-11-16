//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// g582 round 4 (class audit E3): on standalone a vendor policy folder that
// already holds a DefenseClaw file, and that standard users can write, is
// refused and named, not taken over in place. A folder with no DefenseClaw
// file (created before the first install) and Secure Client keep the
// takeover.
func TestWindowsReclaimNeverTakesOverAFolderHoldingDefenseClawFilesOnStandalone(t *testing.T) {
	for _, tc := range []struct {
		name       string
		marker     bool
		standalone bool
		refused    bool
	}{
		{name: "standalone, DefenseClaw file inside", marker: true, standalone: true, refused: true},
		{name: "twin: standalone, created before the first install", standalone: true},
		{name: "twin: Secure Client, DefenseClaw file inside", marker: true},
	} {
		for _, via := range []string{"reconcile", "setup repair"} {
			t.Run(tc.name+" ("+via+")", func(t *testing.T) {
				opts := windowsTestOptions(t)
				github := filepath.Join(opts.WindowsProgramData, "GitHub")
				copilot := filepath.Join(github, "Copilot")
				for _, dir := range []string{github, copilot} {
					if err := createProtectedDir(dir); err != nil {
						t.Fatal(err)
					}
				}
				dir := filepath.Join(copilot, "policy.d")
				const usersAddSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200af;;;BU)"
				sd, err := windows.SecurityDescriptorFromString(usersAddSDDL)
				if err != nil {
					t.Fatal(err)
				}
				attributes := windows.SecurityAttributes{SecurityDescriptor: sd}
				attributes.Length = uint32(unsafe.Sizeof(attributes))
				name, _ := windows.UTF16PtrFromString(dir)
				if err := windows.CreateDirectory(name, &attributes); err != nil {
					t.Fatal(err)
				}
				if tc.marker {
					if err := os.WriteFile(filepath.Join(dir, "50-defenseclaw.json"), []byte("{}"), 0o600); err != nil {
						t.Fatal(err)
					}
					setAdministratorsOwner(t, filepath.Join(dir, "50-defenseclaw.json"))
				}
				previous := reclaimRefusesContentDrift
				reclaimRefusesContentDrift = func() bool { return tc.standalone }
				t.Cleanup(func() { reclaimRefusesContentDrift = previous })

				if via == "reconcile" {
					_, err = reclaimPolicyDirs(opts, dir)
				} else {
					err = RepairWindowsPublicDir(dir)
				}

				usersCanAdd := validateTrustedLeafDir(dir) != nil
				if tc.refused {
					var refused *managed.StandaloneContentDriftError
					if !errors.As(err, &refused) || !strings.Contains(err.Error(), "50-defenseclaw.json") {
						t.Fatalf("err = %v, want a standalone refusal naming the DefenseClaw file", err)
					}
					if !usersCanAdd {
						t.Fatal("the folder was taken over in place")
					}
					return
				}
				if err != nil || usersCanAdd {
					t.Fatalf("err = %v, users can still add = %t; want the folder taken back", err, usersCanAdd)
				}
			})
		}
	}
}
