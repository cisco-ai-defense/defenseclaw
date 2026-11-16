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

//go:build !windows

package connector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestCoworkPluginHooksRunClaudeCodeHandler pins the Cowork plugin to the
// per-user Claude Code handler: the measured Cowork events only, each with
// the Claude Code matcher and timeout, running the Claude Code hook script
// behind the fail-closed missing-script guard. Without a Claude Code setup
// (no lock entry, or no script) it refuses.
func TestCoworkPluginHooksRunClaudeCodeHandler(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data dir")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: dataDir}
	if _, err := CoworkPluginHooks(opts); !errors.Is(err, ErrCoworkClaudeCodeNotSetUp) {
		t.Fatalf("no lock entry: err = %v, want ErrCoworkClaudeCodeNotSetUp", err)
	}
	if err := SaveHookContractLockEntry(dataDir, HookContractLockEntry{Connector: "claudecode", ContractID: "claudecode-test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := CoworkPluginHooks(opts); !errors.Is(err, ErrCoworkClaudeCodeNotSetUp) {
		t.Fatalf("no hook script: err = %v, want ErrCoworkClaudeCodeNotSetUp", err)
	}
	script := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/bash\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := CoworkPluginHooks(SetupOpts{DataDir: dataDir, ManagedEnterprise: true}); err == nil {
		t.Fatal("managed install rendered an account plugin")
	}

	raw, err := CoworkPluginHooks(opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string   `json:"type"`
				Command string   `json:"command"`
				Args    []string `json:"args"`
				Timeout int      `json:"timeout"`
				Async   bool     `json:"async"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var events []string
	for event := range doc.Hooks {
		events = append(events, event)
	}
	sort.Strings(events)
	want := append([]string(nil), CoworkPluginHookEvents...)
	sort.Strings(want)
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", events, want)
	}
	groups := map[string]claudeCodeHookGroup{}
	for _, group := range hookGroups {
		groups[group.eventType] = group
	}
	for event, entries := range doc.Hooks {
		group := groups[event]
		if len(entries) != 1 || len(entries[0].Hooks) != 1 {
			t.Fatalf("%s: %d entries, want one handler", event, len(entries))
		}
		handler := entries[0].Hooks[0]
		if entries[0].Matcher != group.matcher || handler.Timeout != group.timeout || handler.Async {
			t.Fatalf("%s: matcher %q timeout %d async %v, want the Claude Code group %+v",
				event, entries[0].Matcher, handler.Timeout, handler.Async, group)
		}
		if handler.Type != "command" || handler.Args != nil ||
			!strings.Contains(handler.Command, shellSingleQuote(script)) ||
			!strings.Contains(handler.Command, dataDir+coworkRemovalMarkerSuffix) ||
			!strings.Contains(handler.Command, coworkMissingHookGuardMessage) {
			t.Fatalf("%s: handler %+v, want the script, removal record and installed guard", event, handler)
		}
	}
}
