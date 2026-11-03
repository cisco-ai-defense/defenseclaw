// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func perUserLauncherFixture(t *testing.T) (string, string, []byte) {
	t.Helper()
	commandDir := filepath.Join(t.TempDir(), ".local", "bin")
	dataRoot := filepath.Join(t.TempDir(), ".defenseclaw")
	executable := filepath.Join(commandDir, "defenseclaw.exe")
	state, err := json.Marshal(perUserLauncherState{
		SchemaVersion: 1, InstallKind: "powershell-windows", InstallScope: "user",
		DataRoot: dataRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	return executable, dataRoot, state
}

func TestPerUserLauncherNamesReparseDataRootBeforePython(t *testing.T) {
	executable, dataRoot, state := perUserLauncherFixture(t)
	target, handled, err := perUserLauncherTarget(executable, state, "", func(path string) (bool, error) {
		if path != dataRoot {
			t.Fatalf("checked %q, want %q", path, dataRoot)
		}
		return true, nil
	})
	if !handled || target != "" || err == nil || !strings.Contains(err.Error(), dataRoot) || !strings.Contains(err.Error(), "reparse point") || !strings.Contains(err.Error(), "restore the original non-link folder") {
		t.Fatalf("target=%q handled=%v err=%v", target, handled, err)
	}
}

func TestPerUserLauncherAllowsOrdinaryDataRoot(t *testing.T) {
	executable, dataRoot, state := perUserLauncherFixture(t)
	target, handled, err := perUserLauncherTarget(executable, state, "", func(string) (bool, error) { return false, nil })
	if err != nil || !handled || target != filepath.Join(dataRoot, ".venv", "Scripts", "defenseclaw.exe") {
		t.Fatalf("target=%q handled=%v err=%v", target, handled, err)
	}
	selected := filepath.Join(t.TempDir(), "selected")
	checked := []string{}
	_, handled, err = perUserLauncherTarget(executable, state, selected, func(path string) (bool, error) {
		checked = append(checked, path)
		if path == selected {
			return true, nil
		}
		return false, nil
	})
	if !handled || err == nil || !strings.Contains(err.Error(), selected) || fmt.Sprint(checked) != fmt.Sprint([]string{dataRoot, selected}) {
		t.Fatalf("handled=%v err=%v checked=%q", handled, err, checked)
	}
}

func TestPerUserLauncherKeepsOtherExecutablePaths(t *testing.T) {
	executable, _, state := perUserLauncherFixture(t)
	check := func(string) (bool, error) { return false, os.ErrNotExist }
	if _, handled, err := perUserLauncherTarget(filepath.Join(filepath.Dir(executable), "defenseclaw-gateway.exe"), state, "", check); handled || err != nil {
		t.Fatalf("gateway executable handled=%v err=%v", handled, err)
	}
	if _, handled, err := perUserLauncherTarget(executable, []byte(`{"install_kind":"native-windows"}`), "", check); handled || err != nil {
		t.Fatalf("other install handled=%v err=%v", handled, err)
	}
	managedExecutable := filepath.Join(t.TempDir(), "bin", "defenseclaw.exe")
	if _, handled, err := perUserLauncherTarget(managedExecutable, state, "", check); handled || err != nil {
		t.Fatalf("managed executable handled=%v err=%v", handled, err)
	}
}
