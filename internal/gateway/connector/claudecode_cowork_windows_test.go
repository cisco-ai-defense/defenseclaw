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
	"path/filepath"
	"strings"
	"testing"
)

// TestCoworkPluginHooksUseClaudeCodeExecFormOnWindows pins the literal argv of
// the Windows plugin handlers in the one-line install layout (launcher and
// guard side by side): PreToolUse runs the guard program, every other event
// the cmd.exe launcher guard, and no handler is the managed form.
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
	cmdGuard := append([]string{"/d", "/c", "if", "exist", launcher, "(", launcher, "hook", "--connector", "claudecode",
		")", "else", "(", "echo"},
		strings.Fields("DefenseClaw blocked this: its Claude Code hook launcher is missing. Run the DefenseClaw installer again to repair it.")...)
	cmdGuard = append(cmdGuard, "1>&2", "&", "exit", "/b", "2", ")")
	preTool := []string{"launcher-guard", launcher, "hook", "--connector", "claudecode"}
	for event, entries := range doc.Hooks {
		handler := entries[0].Hooks[0]
		got := strings.Join(handler.Args, "\x00")
		if event == "PreToolUse" {
			if !strings.EqualFold(handler.Command, guard) || got != strings.Join(preTool, "\x00") {
				t.Fatalf("PreToolUse: %q %q, want %q %q", handler.Command, handler.Args, guard, preTool)
			}
			continue
		}
		if !strings.EqualFold(filepath.Base(handler.Command), "cmd.exe") || !filepath.IsAbs(handler.Command) ||
			got != strings.Join(cmdGuard, "\x00") {
			t.Fatalf("%s: %q %q, want <system>\\cmd.exe %q", event, handler.Command, handler.Args, cmdGuard)
		}
		if strings.Contains(got, "--enterprise-managed") {
			t.Fatalf("%s: per-user plugin handler carries --enterprise-managed", event)
		}
	}
}
