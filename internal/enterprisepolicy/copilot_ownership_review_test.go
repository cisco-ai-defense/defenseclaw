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

func TestCopilotPolicyRemovalStripsTamperedOwnCommand(t *testing.T) {
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
			if !copilotHandlerIsOwned(opts, map[string]any{
				"type": "command", field: prior, "timeoutSec": 30,
			}) {
				t.Fatal("prior release handler must remain removable during upgrade")
			}
			priorWithCWD := map[string]any{"type": "command", field: prior, "timeoutSec": 30, "cwd": "/tmp"}
			priorDocument, err := json.Marshal(map[string]any{"version": 1, "hooks": map[string]any{"preToolUse": []any{priorWithCWD}}})
			if err != nil {
				t.Fatal(err)
			}
			merged, err := mergeCopilotDropIn(opts, priorDocument)
			if err != nil {
				t.Fatalf("upgrade did not repair prior command with extra data: %v", err)
			}
			rendered, err := renderCopilotDropIn(opts)
			if err != nil || string(merged) != string(rendered) {
				t.Fatalf("upgrade did not publish the current render: %s, %v", merged, err)
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
				map[string]any{"type": "command", field: "operator-tool"},
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
				t.Fatal("DefenseClaw handlers were not removed")
			}
			var got map[string]any
			if err := json.Unmarshal(remaining, &got); err != nil {
				t.Fatal(err)
			}
			entries := got["hooks"].(map[string]any)["preToolUse"].([]any)
			if len(entries) != 1 || entries[0].(map[string]any)[field] != "operator-tool" {
				t.Fatalf("tampered command remained or independent handler was removed: %s", remaining)
			}
		})
	}
}

func TestCopilotManagedReconcileRepairsOwnHandler(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			binary := "/opt/defenseclaw/bin/defenseclaw-hook"
			field, other := "bash", "powershell"
			if goos == "windows" {
				binary = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
				field, other = "powershell", "bash"
			}
			opts := Options{GOOS: goos, HookBinary: binary}
			for _, variant := range []string{"suffix", "suffix with cwd", "suffix with env", "extra field", "timeout with extra field", "type with extra field", "second executable", "suffix with second executable"} {
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
					case "suffix with cwd":
						handler[field] = handler[field].(string) + "; Write-Output operator"
						handler["cwd"] = "/tmp"
					case "suffix with env":
						handler[field] = handler[field].(string) + "; Write-Output operator"
						handler["env"] = map[string]any{}
					case "extra field":
						handler["operator"] = map[string]any{"command": "operator-tool"}
					case "timeout with extra field":
						handler["timeoutSec"] = 1
						handler["cwd"] = "/tmp"
					case "type with extra field":
						handler["type"] = "prompt"
						handler["env"] = map[string]any{"MODE": "changed"}
					case "second executable":
						handler[other] = "operator-tool"
					case "suffix with second executable":
						handler[field] = handler[field].(string) + "; Write-Output operator"
						handler[other] = "operator-tool"
					}
					current, err := json.Marshal(doc)
					if err != nil {
						t.Fatal(err)
					}
					merged, err := mergeCopilotDropIn(opts, current)
					if err != nil || string(merged) != string(document) {
						t.Fatalf("reconcile did not restore its %s handler: returned_document=%s, err=%v", variant, merged, err)
					}
				})
			}
		})
	}
}

func TestCopilotManagedCorruptDropInSelfHeals(t *testing.T) {
	cases := []struct {
		name    string
		current string
	}{
		{"truncated", `{`},
		{"non-object hooks", `{"hooks":false,"operator":{"enabled":true}}`},
		{"array hooks", `{"hooks":[],"operator":{"enabled":true}}`},
		{"non-list event", `{"hooks":{"preToolUse":"x"},"operator":{"enabled":true}}`},
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			opts := Options{GOOS: goos, HookBinary: "/opt/defenseclaw/bin/defenseclaw-hook"}
			if goos == "windows" {
				opts.HookBinary = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					merged, err := mergeCopilotDropIn(opts, []byte(tc.current))
					if err != nil {
						t.Fatalf("repair corrupt drop-in: %v", err)
					}
					var doc map[string]any
					if err := json.Unmarshal(merged, &doc); err != nil {
						t.Fatalf("repair did not publish JSON: %s: %v", merged, err)
					}
					hooks, ok := doc["hooks"].(map[string]any)
					if !ok {
						t.Fatalf("repair did not publish hooks: %s", merged)
					}
					if _, ok := hooks["preToolUse"].([]any); !ok {
						t.Fatalf("repair did not publish managed hooks: %s", merged)
					}
					if strings.Contains(tc.current, "operator") && doc["operator"] == nil {
						t.Fatalf("repair lost independent top-level content: %s", merged)
					}
				})
			}
		})
	}

	opts := testOptions(t)
	opts.CopilotCLIPolicyOnly = true
	path, err := copilotDropInPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run("record "+tc.name, func(t *testing.T) {
			writeFile(t, path, tc.current)
			target := copilotTarget{}
			state, err := target.Reconcile(opts)
			if err != nil || !state.Covered {
				t.Fatalf("reconcile did not restore coverage: %+v, %v", state, err)
			}
			if verified, err := target.Verify(opts); err != nil || !verified.Covered {
				t.Fatalf("verify did not see restored coverage: %+v, %v", verified, err)
			}
			if _, err := target.RemoveOwned(opts); err != nil || readFile(t, path) != tc.current {
				t.Fatalf("uninstall did not restore preimage: %s, %v", readFile(t, path), err)
			}
		})
		t.Run("published "+tc.name, func(t *testing.T) {
			opts := testOptions(t)
			opts.CopilotCLIPolicyOnly = true
			path, err := copilotDropInPath(opts)
			if err != nil {
				t.Fatal(err)
			}
			target := copilotTarget{}
			if _, err := target.Reconcile(opts); err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, tc.current)
			if verified, err := target.Verify(opts); err != nil || verified.Covered {
				t.Fatalf("verify claimed the corrupt drop-in: %+v, %v", verified, err)
			}
			if state, err := target.Reconcile(opts); err != nil || !state.Covered {
				t.Fatalf("reconcile did not restore the published drop-in: %+v, %v", state, err)
			}
		})
	}

	// A valid independent hook is recognizable content, even when a second
	// event is malformed. Reconcile must not discard that hook to repair ours.
	foreign := `{"hooks":{"preToolUse":"x","operatorEvent":[{"type":"command","bash":"/opt/operator/audit.sh"}]}}`
	if merged, err := mergeCopilotDropIn(opts, []byte(foreign)); err == nil || merged != nil {
		t.Fatalf("reconcile discarded a recognizable independent handler: %s, %v", merged, err)
	}
}

func TestCopilotMalformedEventDoesNotClaimCoverage(t *testing.T) {
	opts := testOptions(t)
	opts.CopilotCLIPolicyOnly = true
	path, err := copilotDropInPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	target := copilotTarget{}
	if _, err := target.Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(readFile(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	doc["hooks"].(map[string]any)["operatorEvent"] = "x"
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(edited))
	verified, err := target.Verify(opts)
	if err != nil || verified.Covered || !hasConflict(verified, "operatorEvent is not a handler list") {
		t.Fatalf("verify claimed malformed policy is active: %+v, %v", verified, err)
	}
	state, err := target.Reconcile(opts)
	if err != nil || !state.Covered {
		t.Fatalf("reconcile did not repair malformed policy: %+v, %v", state, err)
	}
}

func TestCopilotForeignMalformedEventIsNotRepairDrift(t *testing.T) {
	opts := testOptions(t)
	opts.CopilotCLIPolicyOnly = true
	target := copilotTarget{}
	if _, err := target.Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	dir, err := CopilotPolicyDir(opts)
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(dir, "operator.json")
	const original = `{"hooks":{"operatorEvent":"not a handler list"}}`
	writeFile(t, foreign, original)
	state, err := target.Verify(opts)
	if err != nil || state.Covered || state.Drift || !hasConflict(state, "outside DefenseClaw ownership") {
		t.Fatalf("verify treated an unowned malformed event as repairable drift: %+v, %v", state, err)
	}
	if state, err := target.Reconcile(opts); err != nil || state.Drift || readFile(t, foreign) != original {
		t.Fatalf("reconcile changed unowned policy: %+v, %v", state, err)
	}
	ownedPath, err := copilotDropInPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	var published map[string]any
	if err := json.Unmarshal([]byte(readFile(t, ownedPath)), &published); err != nil {
		t.Fatal(err)
	}
	copy := published["hooks"].(map[string]any)["preToolUse"]
	foreignDoc, err := json.Marshal(map[string]any{"hooks": map[string]any{"preToolUse": copy, "operatorEvent": "malformed"}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, foreign, string(foreignDoc))
	if err := os.Remove(ownedPath); err != nil {
		t.Fatal(err)
	}
	state, err = target.Verify(opts)
	if err != nil || state.Covered || state.OwnedEntries != 0 || !hasConflict(state, "outside DefenseClaw ownership") {
		t.Fatalf("a copy in an unowned file claimed DefenseClaw coverage or repair: %+v, %v", state, err)
	}
}

func TestCopilotExtraFieldVerifyAndReconcileAgree(t *testing.T) {
	opts := testOptions(t)
	opts.CopilotCLIPolicyOnly = true
	path, err := copilotDropInPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	target := copilotTarget{}
	if _, err := target.Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(readFile(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	pre := doc["hooks"].(map[string]any)["preToolUse"].([]any)[0].(map[string]any)
	pre["operator"] = map[string]any{"command": "operator-tool"}
	doc["hooks"].(map[string]any)["preToolUse"] = append(doc["hooks"].(map[string]any)["preToolUse"].([]any),
		map[string]any{"type": "command", "bash": "/opt/operator/audit.sh"})
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(edited))
	verified, err := target.Verify(opts)
	if err != nil || verified.Covered || !hasConflict(verified, "next lifecycle run") {
		t.Fatalf("verify did not report repairable drift: %+v, %v", verified, err)
	}
	if state, err := target.Reconcile(opts); err != nil || !state.Covered {
		t.Fatalf("reconcile did not repair the extra field: %+v, %v", state, err)
	}
	var repaired map[string]any
	if err := json.Unmarshal([]byte(readFile(t, path)), &repaired); err != nil {
		t.Fatal(err)
	}
	entries := repaired["hooks"].(map[string]any)["preToolUse"].([]any)
	if len(entries) != 2 || entries[0].(map[string]any)["bash"] != "/opt/operator/audit.sh" ||
		entries[1].(map[string]any)["operator"] != nil || !copilotHandlerIsOwned(opts, entries[1]) {
		t.Fatalf("repair did not preserve the separate operator hook: %v", entries)
	}
	entries[1].(map[string]any)["timeoutSec"] = "30"
	changedType, err := json.Marshal(repaired)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(changedType))
	if state, err := target.Verify(opts); err != nil || state.Covered || !hasConflict(state, "timeoutSec") {
		t.Fatalf("verify accepted a string timeout instead of the published number: %+v, %v", state, err)
	}
	if state, err := target.Reconcile(opts); err != nil || !state.Covered {
		t.Fatalf("reconcile did not restore the numeric timeout: %+v, %v", state, err)
	}
}

func TestCopilotManagedNullHooksAreInert(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			opts := Options{GOOS: goos, HookBinary: "/opt/defenseclaw/bin/defenseclaw-hook"}
			if goos == "windows" {
				opts.HookBinary = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
			}
			for _, current := range []string{
				`{"version":1,"hooks":null}`,
				`{"version":1,"hooks":null,"operator":{"enabled":true}}`,
			} {
				merged, err := mergeCopilotDropIn(opts, []byte(current))
				if err != nil {
					t.Fatalf("inert hooks in %s: %v", current, err)
				}
				var doc map[string]any
				if err := json.Unmarshal(merged, &doc); err != nil {
					t.Fatal(err)
				}
				if doc["hooks"] == nil || (strings.Contains(current, "operator") && doc["operator"] == nil) {
					t.Fatalf("publish lost the current hooks or independent top-level content: %s", merged)
				}
			}
		})
	}

	opts := testOptions(t)
	opts.CopilotCLIPolicyOnly = true
	path, err := copilotDropInPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	const original = `{"version":1,"hooks":null,"operator":{"enabled":true}}`
	writeFile(t, path, original)
	target := copilotTarget{}
	state, err := target.Reconcile(opts)
	if err != nil || !state.Covered {
		t.Fatalf("publish did not install hooks in an inert drop-in: %+v, %v", state, err)
	}
	if verified, err := target.Verify(opts); err != nil || !verified.Covered {
		t.Fatalf("verify disagreed with publish: %+v, %v", verified, err)
	}
	if _, err := target.RemoveOwned(opts); err != nil || readFile(t, path) != original {
		t.Fatalf("remove did not restore the independent original: %s, %v", readFile(t, path), err)
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
