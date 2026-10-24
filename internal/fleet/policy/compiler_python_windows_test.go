// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package policy

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Review loop round 4: the policy compiler runs the Python under the
// scanner runtime folder by its path, so it is refused when a standard user
// can replace it through a folder above it (ProgramData\Cisco, or the
// python folder). Before, nothing checked who could change it.
func TestInstalledPythonInterpreterRefusesReplaceRightsAroundIt(t *testing.T) {
	const deleteChildren = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1200e9;;;BU)"
	for _, element := range []string{"", "cisco", "python"} {
		name := "replace right on the " + element + " folder"
		if element == "" {
			name = "stock tree"
		}
		t.Run(name, func(t *testing.T) {
			cisco, root := testenv.CiscoRuntimeTree(t, "DefenseClaw-ScannerRuntime")
			scanner := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
			testenv.WriteAdminOnlyFile(t, scanner, []byte("runtime"))
			digest, err := managed.FileSHA256(scanner)
			if err != nil {
				t.Fatal(err)
			}
			if err := managed.WriteScannerRuntimeAdmission(root, digest, managed.ScannerRuntimeTrustAuthenticode); err != nil {
				t.Fatal(err)
			}
			python := filepath.Join(root, "python", "python.exe")
			testenv.WriteAdminOnlyFile(t, python, []byte("python"))
			seam := windowsScannerRuntimeRoot
			windowsScannerRuntimeRoot = func() (string, error) { return root, nil }
			t.Cleanup(func() { windowsScannerRuntimeRoot = seam })
			target := map[string]string{"cisco": cisco, "python": filepath.Dir(python)}[element]
			if target != "" {
				testenv.SetSecurity(t, target, deleteChildren)
			}
			got, err := installedPythonInterpreter()
			if target == "" {
				if err != nil || got != python {
					t.Fatalf("stock tree: installedPythonInterpreter() = %q, %v; want %s", got, err, python)
				}
				return
			}
			if err == nil || got != "" || !strings.Contains(err.Error(), target) {
				t.Fatalf("installedPythonInterpreter() = %q, %v; want a refusal naming %s", got, err, target)
			}
		})
	}
}
