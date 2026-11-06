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
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// TestCoworkPluginHooksUseClaudeCodeExecFormOnWindows pins the Windows plugin
// handler in the one-line install layout. The native guard checks completed
// removal and runs the launcher while the account is installed.
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
		if handler.Command != guard || !reflect.DeepEqual(handler.Args, []string{hookguard.CoworkSubcommand, dataDir, launcher, event}) {
			t.Fatalf("%s: %q %q does not guard the installed launcher and distinguish removal", event, handler.Command, handler.Args)
		}
		if gotDir, gotLauncher, gotEvent, ok := hookguard.CoworkArgv(handler.Args); !ok ||
			gotDir != dataDir || gotLauncher != launcher || gotEvent != event {
			t.Fatalf("%s: generated arguments are not accepted by the native guard", event)
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
	// An account with no data folder has no Claude Code setup: Cowork setup
	// refuses and creates nothing.
	if _, err := CoworkPluginHooks(SetupOpts{DataDir: dataDir, HookExecutable: launcher}); !errors.Is(err, ErrCoworkClaudeCodeNotSetUp) {
		t.Fatalf("account without a data folder: err = %v, want ErrCoworkClaudeCodeNotSetUp", err)
	}
	if _, err := os.Lstat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Cowork setup created the account data folder: %v", err)
	}
	// defenseclaw init creates the private data folder, and Claude Code setup
	// writes its hooks there before it records the hook contract.
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
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
		gotDir, gotLauncher, event, ok := hookguard.CoworkArgv(handler.Args)
		if !ok || handler.Command != guard {
			t.Fatal("invalid native Cowork guard entry")
		}
		var out bytes.Buffer
		code := hookguard.RunCowork(gotDir, gotLauncher, event, bytes.NewReader(nil), &out, &out)
		return code, out.String()
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
	if _, err := CoworkPluginHooks(SetupOpts{DataDir: dataDir, HookExecutable: launcher}); !errors.Is(err, ErrCoworkClaudeCodeNotSetUp) {
		t.Fatalf("removed guard was accepted at setup: %v", err)
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

func TestCoworkPluginHooksAcceptWindowsAccountPathVariants(t *testing.T) {
	for _, name := range []string{"ordinary", "DC!Ops", "DC%Ops", "DC&Ops", "DC^Ops", "DC(Ops)"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), name)
			dataDir := filepath.Join(root, "account")
			bin := filepath.Join(root, "bin")
			// defenseclaw init creates the private data folder before Claude
			// Code setup records the hook contract in it.
			for _, dir := range []string{dataDir, bin} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			launcher := filepath.Join(bin, "defenseclaw-hook.exe")
			guard := filepath.Join(bin, "defenseclaw-hook-guard.exe")
			for _, path := range []string{launcher, guard} {
				if err := os.WriteFile(path, []byte("MZ"), 0o700); err != nil {
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
			for _, event := range []string{"PreToolUse", "UserPromptSubmit"} {
				handler := doc.Hooks[event][0].Hooks[0]
				if handler.Command != guard || !reflect.DeepEqual(handler.Args, []string{hookguard.CoworkSubcommand, dataDir, launcher, event}) {
					t.Fatalf("%s: command %q args %q, want literal native guard arguments", event, handler.Command, handler.Args)
				}
			}
		})
	}
}
