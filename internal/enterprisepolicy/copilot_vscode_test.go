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

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestCopilotVSCodeLocalAndManagedSettings covers the per-user Local hook
// file and plugin (written, recognized as DefenseClaw's by the guard, never
// overwriting a user's file) and the managed-settings keys (plugin enabled,
// the managed-only lock only once its gate passes, removal keeping the
// administrator's keys).
func TestCopilotVSCodeLocalAndManagedSettings(t *testing.T) {
	home := t.TempDir()
	ensure := func(hookFile, plugin bool) CopilotVSCodeUserResult {
		t.Helper()
		result, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{
			Home: home, GOOS: "linux", HookBinary: testHookBinary, HookFile: hookFile, Plugin: plugin,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := ensure(true, true); !result.HookFileOK || !result.PluginOK || len(result.Changed) != 3 {
		t.Fatalf("first placement: %+v", result)
	}
	hookFile := CopilotVSCodeLocalHookFilePath(home)
	if !(GuardRequest{GOOS: "linux", HookBinary: testHookBinary}).ownedHooksDocument([]byte(readFile(t, hookFile))) {
		t.Fatal("the guard does not recognize the Local hook file as DefenseClaw's")
	}
	if result := ensure(true, true); len(result.Changed) != 0 || !result.PluginOK {
		t.Fatalf("second placement not idempotent: %+v", result)
	}

	opts := withPolicy(testOptions(t), copilotConnector, func(p *config.EnterpriseConnectorPolicy) {
		p.ManagedHooksOnly = config.ManagedHooksOnlyEnforce
	})
	opts.CopilotUserHomes = []string{home}
	settings, err := CopilotManagedSettingsPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, settings, `{"model":"admin"}`)
	reconcile := func() string {
		t.Helper()
		if err := copilotManagedSettings(opts, &State{}, true); err != nil {
			t.Fatal(err)
		}
		return readFile(t, settings)
	}
	if got := reconcile(); !strings.Contains(got, CopilotPluginKey) || strings.Contains(got, copilotSettingHooksOnly) {
		t.Fatalf("without a VS Code in the lock window: %s", got)
	}
	writeFile(t, rooted(opts, "/usr/share/code/resources/app/package.json"), `{"version":"1.139.2"}`)
	if got := reconcile(); !strings.Contains(got, copilotSettingHooksOnly) || !strings.Contains(got, `"admin"`) {
		t.Fatalf("lock not set once the gate passed: %s", got)
	}
	if err := removeCopilotManagedSettings(opts, &State{}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, settings); strings.Contains(got, CopilotPluginKey) || strings.Contains(got, copilotSettingHooksOnly) || !strings.Contains(got, `"admin"`) {
		t.Fatalf("removal: %s", got)
	}

	foreign := `{"hooks":{"PreToolUse":[{"type":"command","command":"user-tool"}]}}`
	writeFile(t, hookFile, foreign)
	if result := ensure(false, false); len(result.Kept) != 1 || result.Kept[0] != hookFile {
		t.Fatalf("user's hook file not kept: %+v", result)
	}
	if got := readFile(t, hookFile); got != foreign {
		t.Fatalf("user's hook file changed: %s", got)
	}
	if _, err := os.Stat(filepath.Dir(CopilotPluginDir(home))); !os.IsNotExist(err) {
		t.Fatalf("plugin directories left behind: %v", err)
	}
}

func TestCopilotVSCodeRepairsAnEmptiedHookFile(t *testing.T) {
	home := t.TempDir()
	run := func(keep, dryRun bool) CopilotVSCodeUserResult {
		t.Helper()
		result, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{
			Home: home, GOOS: "linux", HookBinary: testHookBinary, HookFile: keep, DryRun: dryRun,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	run(true, false)
	hookFile := CopilotVSCodeLocalHookFilePath(home)
	if err := os.WriteFile(hookFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result := run(true, true); len(result.Changed) != 1 || len(result.Kept) != 0 {
		t.Fatalf("verify must report the emptied hook file as drift: %+v", result)
	}
	if result := run(true, false); !result.HookFileOK {
		t.Fatalf("setup must repair the emptied hook file: %+v", result)
	}
	if err := os.WriteFile(hookFile, []byte(`{"hooks":{"PreToolUse":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if result := run(false, false); len(result.Removed) != 1 {
		t.Fatalf("uninstall must remove the emptied hook file: %+v", result)
	}
	if _, err := os.Stat(hookFile); !os.IsNotExist(err) {
		t.Fatalf("hook file left behind: %v", err)
	}
}
