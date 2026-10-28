// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Review loop round 4: the lifecycle runs the scanner executable elevated by
// its path, so a standard user who can delete the children of
// ProgramData\Cisco (and so swap the runtime folder between the check and
// the run) makes status and verify report it untrusted and not run it, the
// service check (the gateway's) fail, the staged payload copy refuse to run,
// and the staged payload itself refuse to be admitted. Before, the walk only
// warned for ProgramData\Cisco: status ran the executable, and an install
// ran the copy's prepare.
func TestWindowsScannerRuntimeRefusesReplaceRightsAboveItsFolder(t *testing.T) {
	const deleteChildren = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1200e9;;;BU)"
	cisco, root := testenv.CiscoRuntimeTree(t, "DefenseClaw-ScannerRuntime")
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	testenv.WriteAdminOnlyFile(t, target, []byte("installed runtime"))
	digest, err := windowsEnterpriseFileSHA256(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := managed.WriteScannerRuntimeAdmission(root, digest, managed.ScannerRuntimeTrustAuthenticode); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(cisco, "Staging", managed.StandaloneWindowsScannerRuntimeName)
	testenv.WriteAdminOnlyFile(t, source, []byte("staged runtime"))
	installer := filepath.Join(filepath.Dir(source), "install-enterprise.ps1")
	testenv.WriteAdminOnlyFile(t, installer, []byte("installer"))
	staged, err := windowsEnterpriseFileSHA256(source)
	if err != nil {
		t.Fatal(err)
	}
	dirSeam, accountSeam, sourceSeam := windowsScannerRuntimeDir, windowsScannerGatewayAccount, windowsScannerSourceCheck
	t.Cleanup(func() {
		windowsScannerRuntimeDir, windowsScannerGatewayAccount, windowsScannerSourceCheck = dirSeam, accountSeam, sourceSeam
	})
	windowsScannerRuntimeDir = func() (string, error) { return root, nil }
	// The gateway service is not installed here; any service SID will do.
	windowsScannerGatewayAccount = `NT SERVICE\TrustedInstaller`
	setWindowsScannerRuntimeDeploymentTest(t, func() winpath.EnterpriseDeployment {
		return winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.4"}
	})
	pinned := &windowsEnterpriseLifecycleOptions{resolvedInstaller: installer, trustMode: windowsEnterpriseTrustHashPinned,
		productVersion: "1.0.4", payloadPins: map[string]string{managed.StandaloneWindowsScannerRuntimeName: staged}}

	// Control: on the stock tree the runtime is trusted and admitted, so
	// status goes on to run it (it is no executable, so it is not prepared),
	// and the staged payload is admitted.
	if got := readWindowsScannerRuntime(); got.State != "not_prepared" {
		t.Fatalf("stock tree: scanners = %+v, want not_prepared", got)
	}
	if _, err := admitWindowsScannerRuntimePayload(source, staged, pinned); err != nil {
		t.Fatalf("stock tree: the staged payload was refused: %v", err)
	}

	testenv.SetSecurity(t, cisco, deleteChildren)
	got := readWindowsScannerRuntime()
	if got.State != "untrusted" || !strings.Contains(got.Problem, cisco) {
		t.Fatalf("scanners = %+v, want untrusted naming %s", got, cisco)
	}
	if advice := windowsScannerRuntimeUnavailable(got); !strings.Contains(advice, "folder above the runtime") || !strings.Contains(advice, "/repair") {
		t.Fatalf("advice %q does not say to remove the access on the folder above", advice)
	}
	if err := windowsScannerRuntimeServiceCheck(); err == nil || !strings.Contains(err.Error(), cisco) || !strings.Contains(err.Error(), "write-like") {
		t.Fatalf("service check = %v, want the replace right on %s", err, cisco)
	}
	if _, err := admitWindowsScannerRuntimePayload(source, staged, pinned); err == nil || !strings.Contains(err.Error(), cisco) {
		t.Fatalf("the staged payload under %s was admitted: %v", cisco, err)
	}
	// The copy is never run: the install fails on the replace right, the
	// installed executable stays, and no temporary copy is left.
	windowsScannerSourceCheck = func(string, string) error { return nil }
	err = installWindowsScannerRuntime(source, "ensure", pinned)
	if err == nil || !strings.Contains(err.Error(), cisco) {
		t.Fatalf("install = %v, want the replace right on %s", err, cisco)
	}
	if body, _ := os.ReadFile(target); string(body) != "installed runtime" {
		t.Fatalf("installed runtime = %q, want it unchanged", body)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".scanners-") {
			t.Fatalf("the refused copy %s was left in the runtime folder", entry.Name())
		}
	}
}
