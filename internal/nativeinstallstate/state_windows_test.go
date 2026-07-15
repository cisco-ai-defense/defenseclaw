// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package nativeinstallstate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLoadAtRejectsInstallerJunctionSwappedBeforeStateOpen(t *testing.T) {
	state, executable := fixtureState(t)
	installer := filepath.Join(state.InstallRoot, "installer")
	parked := filepath.Join(state.InstallRoot, "installer-original")
	malicious := filepath.Join(t.TempDir(), "attacker-installer")
	if err := os.MkdirAll(malicious, 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(installer, "install-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(malicious, "install-state.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	var junctionErr error
	nativeInstallStateBeforeOpen = func(string) error {
		if err := os.Rename(installer, parked); err != nil {
			return err
		}
		output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", installer, malicious).CombinedOutput()
		if err != nil {
			junctionErr = fmt.Errorf("mklink /J: %w: %s", err, output)
			return junctionErr
		}
		return nil
	}
	t.Cleanup(func() {
		nativeInstallStateBeforeOpen = nil
		_ = os.Remove(installer)
		_ = os.Rename(parked, installer)
	})

	if _, err := loadAt(executable, state.InstallRoot); err == nil {
		t.Fatal("state opened through a junction swapped in after path validation")
	}
	if junctionErr != nil {
		t.Skipf("directory junctions are unavailable: %v", junctionErr)
	}
}
