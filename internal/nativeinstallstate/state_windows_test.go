// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package nativeinstallstate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func junctionsUnavailable(output []byte) bool {
	message := strings.ToLower(string(output))
	for _, marker := range []string{
		"the file system does not support reparse points",
		"the requested operation requires elevation",
		"you do not have sufficient privilege",
		"a required privilege is not held by the client",
		"access is denied",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

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
	var junctionOutput []byte
	nativeInstallStateBeforeOpen = func(string) error {
		if err := os.Rename(installer, parked); err != nil {
			return err
		}
		output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", installer, malicious).CombinedOutput()
		if err != nil {
			junctionOutput = output
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
		if junctionsUnavailable(junctionOutput) {
			t.Skipf("directory junctions are unavailable: %v", junctionErr)
		}
		t.Fatalf("create directory junction: %v", junctionErr)
	}
}

func TestJunctionsUnavailableRecognizesOnlyEnvironmentLimitations(t *testing.T) {
	for _, output := range []string{
		"The file system does not support reparse points.",
		"A required privilege is not held by the client.",
		"Access is denied.",
	} {
		if !junctionsUnavailable([]byte(output)) {
			t.Fatalf("recognized junction limitation was not classified: %q", output)
		}
	}
	for _, output := range []string{
		"The syntax of the command is incorrect.",
		"Cannot create a file when that file already exists.",
		"The system cannot find the path specified.",
	} {
		if junctionsUnavailable([]byte(output)) {
			t.Fatalf("unexpected mklink failure was classified as unavailable: %q", output)
		}
	}
}
