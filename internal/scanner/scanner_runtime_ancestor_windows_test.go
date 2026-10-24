// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package scanner

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Review loop round 4: every scan runs the installed scanner runtime by its
// path, so the gateway refuses it when a standard user can replace it
// through a folder above it (delete the children of ProgramData\Cisco) or
// add a file beside it (a library the executable would load). Before, both
// folders were only warned about, so the scan ran it.
func TestInstalledScannerRuntimeRefusesReplaceRightsAroundIt(t *testing.T) {
	const trustedDACL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	for _, tc := range []struct {
		name, element, ace string
	}{
		{name: "stock tree"},
		{name: "Users can delete the children of Cisco", element: "cisco", ace: "(A;;0x1200e9;;;BU)"},
		{name: "Users can add a file beside the executable", element: "root", ace: "(A;;0x1200ab;;;BU)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cisco, root := testenv.CiscoRuntimeTree(t, "DefenseClaw-ScannerRuntime")
			path := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
			testenv.WriteAdminOnlyFile(t, path, []byte("runtime"))
			digest, err := managed.FileSHA256(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := managed.WriteScannerRuntimeAdmission(root, digest, managed.ScannerRuntimeTrustAuthenticode); err != nil {
				t.Fatal(err)
			}
			oldRoot := scannerRuntimeRoot
			scannerRuntimeRoot = func() (string, error) { return root, nil }
			t.Cleanup(func() { scannerRuntimeRoot = oldRoot })
			target := map[string]string{"cisco": cisco, "root": root}[tc.element]
			if target != "" {
				testenv.SetSecurity(t, target, trustedDACL+tc.ace)
			}
			got, err := installedScannerRuntime()
			if target == "" {
				if err != nil || got != path {
					t.Fatalf("stock tree: installedScannerRuntime() = %q, %v; want %s", got, err, path)
				}
				return
			}
			if err == nil || got != "" || !strings.Contains(err.Error(), target) {
				t.Fatalf("installedScannerRuntime() = %q, %v; want a refusal naming %s", got, err, target)
			}
			if scannerRuntimePath() != "" || scannerRuntimeProblem() == nil {
				t.Fatal("the scan would still run the runtime")
			}
		})
	}
}
