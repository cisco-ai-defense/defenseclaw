// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnterpriseHookManagedInstallLayout(t *testing.T) {
	sep := string(filepath.Separator)
	programFiles := filepath.Join(sep, "Program Files")
	programData := filepath.Join(sep, "ProgramData")
	install := filepath.Join(programFiles, "Cisco", "Cisco Secure Client", "DefenseClaw")
	state := filepath.Join(programData, "Cisco", "Cisco Secure Client", "DefenseClaw")
	executable := filepath.Join(install, "bin", "defenseclaw.exe")
	dataDir := filepath.Join(state, "runtime")
	manifest := filepath.Join(state, "hook-guardian", "targets.yaml")

	layout, ok := enterpriseHookManagedInstallLayout(executable, dataDir, manifest, programFiles, programData)
	if !ok || layout.InstallRoot != install || layout.StateRoot != state ||
		layout.IPCDirectory != filepath.Join(install, "ipc") {
		t.Fatalf("production layout = %+v, %t", layout, ok)
	}

	// A side-by-side install keeps its own roots but never the shared IPC
	// folder.
	certInstall := filepath.Join(programFiles, "DefenseClawCert", "abc")
	layout, ok = enterpriseHookManagedInstallLayout(
		filepath.Join(certInstall, "bin", "defenseclaw.exe"), dataDir, manifest, programFiles, programData)
	if !ok || layout.InstallRoot != certInstall || layout.IPCDirectory != "" {
		t.Fatalf("side-by-side layout = %+v, %t", layout, ok)
	}

	cases := map[string]struct {
		executable, dataDir, manifest string
		wantInstall, wantState        bool
	}{
		"executable outside bin":             {filepath.Join(install, "defenseclaw.exe"), dataDir, manifest, false, true},
		"install root is Program Files":      {filepath.Join(programFiles, "bin", "defenseclaw.exe"), dataDir, manifest, false, true},
		"install root outside Program Files": {filepath.Join(sep, "tmp", "x", "bin", "defenseclaw.exe"), dataDir, manifest, false, true},
		"data dir not runtime":               {executable, filepath.Join(state, "data"), manifest, true, false},
		"state root outside ProgramData":     {executable, filepath.Join(sep, "Users", "u", "runtime"), "", true, false},
		"manifest under another root": {executable, dataDir,
			filepath.Join(programData, "Other", "hook-guardian", "targets.yaml"), true, false},
		"no manifest pinned": {executable, dataDir, "", true, true},
	}
	for name, tc := range cases {
		layout, ok := enterpriseHookManagedInstallLayout(tc.executable, tc.dataDir, tc.manifest, programFiles, programData)
		if (layout.InstallRoot != "") != tc.wantInstall || (layout.StateRoot != "") != tc.wantState ||
			ok != (tc.wantInstall || tc.wantState) {
			t.Errorf("%s: layout = %+v, ok %t", name, layout, ok)
		}
	}

	// A hook started from a launch folder (GAP-0751) repairs the install
	// root of its bin (review 1 P3-5). Windows paths only.
	if runtime.GOOS == "windows" {
		// The launch image parser takes drive-qualified paths only, so this
		// block names the install on C: (the cases above are drive-less).
		driveFiles := `C:\Program Files`
		driveInstall := filepath.Join(driveFiles, "Cisco", "Cisco Secure Client", "DefenseClaw")
		launch := filepath.Join(driveInstall, "bin", "hooks", "0123456789abcdef", "defenseclaw-hook.exe")
		layout, ok = enterpriseHookManagedInstallLayout(launch, dataDir, manifest, driveFiles, programData)
		if !ok || layout.InstallRoot != driveInstall {
			t.Fatalf("launch folder hook layout = %+v, %t", layout, ok)
		}
		other := filepath.Join(driveInstall, "bin", "other", "0123456789abcdef", "defenseclaw-hook.exe")
		if layout, _ := enterpriseHookManagedInstallLayout(other, dataDir, manifest, driveFiles, programData); layout.InstallRoot != "" {
			t.Fatalf("a hook outside bin and its launch folders got the install root %s", layout.InstallRoot)
		}
	}

	if _, ok := enterpriseHookManagedInstallLayout(executable, dataDir, manifest, "", ""); ok {
		t.Fatal("layout derived without trusted roots")
	}
}
