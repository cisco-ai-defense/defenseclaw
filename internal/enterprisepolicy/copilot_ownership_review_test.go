// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestCopilotManagedDropInPreservesIndependentHandlers(t *testing.T) {
	opts := testOptions(t)
	opts.CopilotCLIPolicyOnly = true
	path, err := copilotDropInPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (copilotTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	addIndependent := func() {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal([]byte(readFile(t, path)), &doc); err != nil {
			t.Fatal(err)
		}
		hooks := doc["hooks"].(map[string]any)
		hooks["preToolUse"] = append(hooks["preToolUse"].([]any), map[string]any{
			"type": "command", "bash": "/opt/operator/audit.sh", "timeoutSec": 5,
		})
		hooks["operatorEvent"] = []any{map[string]any{"type": "command", "bash": "/opt/operator/other.sh"}}
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, string(data))
	}
	assertIndependent := func(phase string) {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal([]byte(readFile(t, path)), &doc); err != nil {
			t.Fatal(err)
		}
		hooks := doc["hooks"].(map[string]any)
		if len(hooks["preToolUse"].([]any)) == 0 || hooks["operatorEvent"] == nil {
			t.Fatalf("%s deleted an independent handler: %v", phase, hooks)
		}
		found := false
		for _, raw := range hooks["preToolUse"].([]any) {
			if raw.(map[string]any)["bash"] == "/opt/operator/audit.sh" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s deleted the independent bound-event handler: %v", phase, hooks)
		}
	}
	addIndependent()
	if _, err := (copilotTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	assertIndependent("reconcile")
	if _, err := (copilotTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	assertIndependent("remove")
	var doc map[string]any
	if err := json.Unmarshal([]byte(readFile(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	for _, raw := range doc["hooks"].(map[string]any)["preToolUse"].([]any) {
		if copilotHandlerIsOwned(opts, raw) {
			t.Fatalf("remove left DefenseClaw's hook: %v", raw)
		}
	}
}

func TestCopilotPolicyRemovalKeepsCommandWithOperatorStatement(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			binary := "/opt/defenseclaw/bin/defenseclaw-hook"
			if goos == "windows" {
				binary = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
			}
			opts := Options{GOOS: goos, HookBinary: binary}
			field := "bash"
			if goos == "windows" {
				field = "powershell"
			}
			published := stringField(copilotHandler(opts, "preToolUse", 30), field)
			prior := published
			if goos == "windows" {
				prior = strings.Replace(prior, connector.CopilotRemovedDeploymentGuardPowerShell(binary)+"; ", "", 1)
			} else {
				prior = strings.TrimPrefix(prior, connector.CopilotRemovedDeploymentGuardPOSIX(binary))
			}
			if !copilotHandlerIsRemovable(opts, "preToolUse", map[string]any{
				"type": "command", field: prior, "timeoutSec": 30,
			}) {
				t.Fatal("prior release handler must remain removable during upgrade")
			}
			operator := published + "; "
			if goos == "windows" {
				operator += "Write-Output operator"
			} else {
				operator += "printf operator"
			}
			document := map[string]any{"version": 1, "hooks": map[string]any{"preToolUse": []any{
				map[string]any{"type": "command", field: published, "timeoutSec": 30},
				map[string]any{"type": "command", field: operator, "timeoutSec": 30},
			}}}
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			remaining, removed, err := copilotStrip(opts)(data)
			if err != nil {
				t.Fatal(err)
			}
			if !removed {
				t.Fatal("published handler was not removed")
			}
			var got map[string]any
			if err := json.Unmarshal(remaining, &got); err != nil {
				t.Fatal(err)
			}
			entries := got["hooks"].(map[string]any)["preToolUse"].([]any)
			if len(entries) != 1 || entries[0].(map[string]any)[field] != operator {
				t.Fatalf("operator statement was removed: %s", remaining)
			}
		})
	}
}

func TestCopilotManagedReconcileRefusesCombinedHandler(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			binary := "/opt/defenseclaw/bin/defenseclaw-hook"
			field, other := "bash", "powershell"
			if goos == "windows" {
				binary = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
				field, other = "powershell", "bash"
			}
			opts := Options{GOOS: goos, HookBinary: binary}
			for _, variant := range []string{"suffix", "extra field", "second executable"} {
				t.Run(variant, func(t *testing.T) {
					document, err := renderCopilotDropIn(opts)
					if err != nil {
						t.Fatal(err)
					}
					var doc map[string]any
					if err := json.Unmarshal(document, &doc); err != nil {
						t.Fatal(err)
					}
					handler := doc["hooks"].(map[string]any)["preToolUse"].([]any)[0].(map[string]any)
					switch variant {
					case "suffix":
						handler[field] = handler[field].(string) + "; Write-Output operator"
					case "extra field":
						handler["operator"] = map[string]any{"command": "operator-tool"}
					case "second executable":
						handler[other] = "operator-tool"
					}
					current, err := json.Marshal(doc)
					if err != nil {
						t.Fatal(err)
					}
					if merged, err := mergeCopilotDropIn(opts, current); err == nil || merged != nil ||
						!strings.Contains(err.Error(), "move independent content to a separate handler") {
						t.Fatalf("reconcile claimed a combined %s handler: returned_document=%t, err=%v", variant, merged != nil, err)
					}
				})
			}
		})
	}
}

func TestCopilotLocalRemovalKeepsIndependentHandler(t *testing.T) {
	home := t.TempDir()
	req := CopilotVSCodeUserRequest{Home: home, GOOS: "linux", HookBinary: testHookBinary, HookFile: true}
	if _, err := EnsureCopilotVSCodeUser(req); err != nil {
		t.Fatal(err)
	}
	path := CopilotVSCodeLocalHookFilePath(home)
	var doc map[string]any
	if err := json.Unmarshal([]byte(readFile(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	hooks := doc["hooks"].(map[string]any)
	hooks["PreToolUse"] = append(hooks["PreToolUse"].([]any), map[string]any{
		"type": "command", "command": "/opt/operator/audit.sh",
	})
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// A managed setup cannot claim this mixed file as its own render.
	if result, err := EnsureCopilotVSCodeUser(req); err == nil && result.HookFileOK {
		t.Fatalf("setup claimed a file with an independent hook: %+v", result)
	}
	if _, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{Home: home, GOOS: "linux", HookBinary: testHookBinary}); err != nil {
		t.Fatal(err)
	}
	remaining, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var kept map[string]any
	if err := json.Unmarshal(remaining, &kept); err != nil {
		t.Fatalf("removal damaged the independent hook: %s", remaining)
	}
	entries := kept["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(entries) != 1 || entries[0].(map[string]any)["command"] != "/opt/operator/audit.sh" {
		t.Fatalf("removal changed independent hook: %s", remaining)
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("independent hook directory was removed: %v", err)
	}
}

func TestCopilotPluginRemovalStripsOnlyItsOwnHandlers(t *testing.T) {
	home := t.TempDir()
	req := CopilotVSCodeUserRequest{Home: home, GOOS: "linux", HookBinary: testHookBinary, HookFile: true, Plugin: true}
	if _, err := EnsureCopilotVSCodeUser(req); err != nil {
		t.Fatal(err)
	}
	path := CopilotPluginHooksPath(home)
	var doc map[string]any
	if err := json.Unmarshal([]byte(readFile(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	hooks := doc["hooks"].(map[string]any)
	hooks["PreToolUse"] = append(hooks["PreToolUse"].([]any), map[string]any{
		"type": "command", "command": "/opt/operator/audit.sh",
	})
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := EnsureCopilotVSCodeUser(req); err == nil && result.PluginOK {
		t.Fatalf("setup claimed a plugin with an independent handler: %+v", result)
	}
	if _, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{Home: home, GOOS: "linux", HookBinary: testHookBinary}); err != nil {
		t.Fatal(err)
	}
	var kept map[string]any
	if err := json.Unmarshal([]byte(readFile(t, path)), &kept); err != nil {
		t.Fatal(err)
	}
	entries := kept["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(entries) != 1 || entries[0].(map[string]any)["command"] != "/opt/operator/audit.sh" {
		t.Fatalf("plugin cleanup did not preserve exactly the independent handler: %s", readFile(t, path))
	}
	if _, err := os.Stat(filepath.Join(CopilotPluginDir(home), "plugin.json")); err != nil {
		t.Fatalf("independent plugin lost its manifest: %v", err)
	}
}
