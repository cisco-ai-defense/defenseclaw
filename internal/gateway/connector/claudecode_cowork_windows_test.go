// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCoworkPluginHooksUseClaudeCodeExecFormOnWindows pins the Windows plugin
// handler in the one-line install layout. The cmd.exe entry checks completed
// removal and runs the launcher guard while the account is installed.
func TestCoworkPluginHooksUseClaudeCodeExecFormOnWindows(t *testing.T) {
	dataDir := t.TempDir()
	bin := t.TempDir()
	launcher := filepath.Join(bin, "defenseclaw-hook.exe")
	guard := filepath.Join(bin, "defenseclaw-hook-guard.exe")
	opts := SetupOpts{DataDir: dataDir, HookExecutable: launcher}
	if err := SaveHookContractLockEntry(dataDir, HookContractLockEntry{Connector: "claudecode", ContractID: "claudecode-test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := CoworkPluginHooks(opts); !errors.Is(err, ErrCoworkClaudeCodeNotSetUp) {
		t.Fatalf("missing launcher: err = %v, want ErrCoworkClaudeCodeNotSetUp", err)
	}
	for _, path := range []string{launcher, guard} {
		if err := os.WriteFile(path, []byte("MZ"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := CoworkPluginHooks(opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Hooks) != len(CoworkPluginHookEvents) {
		t.Fatalf("%d events, want %d", len(doc.Hooks), len(CoworkPluginHookEvents))
	}
	for event, entries := range doc.Hooks {
		handler := entries[0].Hooks[0]
		got := strings.Join(handler.Args, "\x00")
		if !strings.EqualFold(filepath.Base(handler.Command), "cmd.exe") || !filepath.IsAbs(handler.Command) ||
			!strings.Contains(got, dataDir+coworkRemovalMarkerSuffix) ||
			!strings.Contains(got, filepath.Join(dataDir, "config.yaml")) ||
			!strings.Contains(got, filepath.Join(dataDir, hookContractLockFile)) ||
			!strings.Contains(got, filepath.Join(dataDir, "gateway.pid")) ||
			!strings.Contains(got, guard+"\x00launcher-guard\x00"+launcher) ||
			!strings.Contains(got, "if\x00errorlevel\x001\x00exit\x00/b\x002") {
			t.Fatalf("%s: %q %q does not guard the installed launcher and distinguish removal", event, handler.Command, handler.Args)
		}
		if strings.Contains(got, "--enterprise-managed") {
			t.Fatalf("%s: per-user plugin handler carries --enterprise-managed", event)
		}
	}
}

func TestCoworkWindowsPluginDistinguishesRemovalFromLauncherFailure(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "account data")
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(bin, "defenseclaw-hook.exe")
	guard := filepath.Join(bin, "defenseclaw-hook-guard.exe")
	for _, path := range []string{launcher, guard} {
		if err := os.WriteFile(path, []byte("not an executable"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := SaveHookContractLockEntry(dataDir, HookContractLockEntry{Connector: "claudecode", ContractID: "claudecode-test"}); err != nil {
		t.Fatal(err)
	}
	raw, err := CoworkPluginHooks(SetupOpts{DataDir: dataDir, HookExecutable: launcher})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	run := func() (int, string) {
		t.Helper()
		handler := doc.Hooks["PreToolUse"][0].Hooks[0]
		out, err := exec.Command(handler.Command, handler.Args...).CombinedOutput()
		if err == nil {
			return 0, string(out)
		}
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), string(out)
		}
		t.Fatal(err)
		return -1, ""
	}
	if code, out := run(); code != 2 {
		t.Fatalf("launcher cannot start: exit %d output %q, want 2", code, out)
	}
	if err := os.Remove(launcher); err != nil {
		t.Fatal(err)
	}
	if code, out := run(); code != 2 {
		t.Fatalf("launcher missing with installed data: exit %d output %q, want 2", code, out)
	}
	if err := os.WriteFile(launcher, []byte("not an executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(guard); err != nil {
		t.Fatal(err)
	}
	if code, out := run(); code != 2 {
		t.Fatalf("launcher guard missing: exit %d output %q, want 2", code, out)
	}
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataDir+coworkRemovalMarkerSuffix, []byte("removed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := run(); code != 0 || !strings.Contains(out, "Customize") {
		t.Fatalf("completed removal: exit %d output %q, want notice", code, out)
	}
}
