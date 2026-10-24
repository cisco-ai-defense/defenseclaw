// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCopilotSetupRepairsDeletedBoundCopy(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "defenseclaw.json")
			current := filepath.Join(root, "current", "copilot-hook.sh")
			old := filepath.Join(root, "deleted", "copilot-hook.sh")
			if goos == "windows" {
				current = windowsCopilotPowerShellAdapterCommand(current)
				old = windowsCopilotPowerShellAdapterCommand(old)
			}
			field := "bash"
			if goos == "windows" {
				field = "powershell"
			}
			stale := map[string]interface{}{
				"hooks": map[string]interface{}{
					"preToolUse": []interface{}{map[string]interface{}{
						"type": "command", field: copilotHookInvocationCommandForEvent(goos, "preToolUse", old),
					}},
				},
			}
			if err := writeJSONObject(path, stale); err != nil {
				t.Fatal(err)
			}
			if err := patchCopilotHooksForOS(path, current, []string{"preToolUse"}, goos); err != nil {
				t.Fatalf("Setup refused a deleted DefenseClaw copy: %v", err)
			}
			got := decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})["preToolUse"]
			want := []interface{}{copilotHookRegistration(goos, "preToolUse", current)}
			if !sameHookJSON(got, want) {
				t.Fatalf("repaired handler = %v, want %v", got, want)
			}
		})
	}
}

func TestCopilotSetupAndTeardownPreserveIndependentNestedHandler(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "defenseclaw.json")
	script := filepath.Join(root, "hooks", "copilot-hook.sh")
	operator := map[string]interface{}{"type": "command", "bash": "/opt/operator/audit.sh"}
	seed := func() {
		t.Helper()
		if err := patchCopilotHooksForOS(path, script, []string{"preToolUse"}, "linux"); err != nil {
			t.Fatal(err)
		}
		cfg := decodeHookFileForTest(t, path)
		hooks := cfg["hooks"].(map[string]interface{})
		hooks["extraEvent"] = map[string]interface{}{"handlers": []interface{}{
			copilotHookRegistration("linux", "preToolUse", script), operator,
		}}
		if err := writeJSONObject(path, cfg); err != nil {
			t.Fatal(err)
		}
	}
	check := func(phase string) {
		t.Helper()
		cfg := decodeHookFileForTest(t, path)
		hooks := cfg["hooks"].(map[string]interface{})
		want := map[string]interface{}{"handlers": []interface{}{operator}}
		if !reflect.DeepEqual(hooks["extraEvent"], want) {
			t.Fatalf("%s changed independent handler: got %v, want %v", phase, hooks["extraEvent"], want)
		}
	}
	seed()
	if err := patchCopilotHooksForOS(path, script, []string{"preToolUse"}, "linux"); err != nil {
		t.Fatal(err)
	}
	check("Setup")
	seed()
	if err := removeCopilotHookReferences(path, script); err != nil {
		t.Fatal(err)
	}
	check("teardown")
}

func TestCopilotSecureClientTeardownPreservesIndependentHandler(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "defenseclaw.json")
	script := filepath.Join(root, "hooks", "copilot-hook.sh")
	operator := map[string]interface{}{"type": "command", "bash": "/opt/operator/audit.sh"}
	doc := map[string]interface{}{"hooks": map[string]interface{}{"extraEvent": []interface{}{
		map[string]interface{}{"handlers": []interface{}{copilotHookRegistration("linux", "preToolUse", script), operator}},
	}}}
	if err := writeJSONObject(path, doc); err != nil {
		t.Fatal(err)
	}
	if err := removeCopilotHookReferencesProfile(path, true, script); err != nil {
		t.Fatal(err)
	}
	hooks, ok := decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})
	if !ok {
		t.Fatal("Secure Client teardown removed the hook document containing an independent handler")
	}
	want := []interface{}{map[string]interface{}{"handlers": []interface{}{operator}}}
	if !sameHookJSON(hooks["extraEvent"], want) {
		t.Fatalf("Secure Client teardown removed an independent handler: %v", hooks["extraEvent"])
	}
}

func TestCopilotCleanupKeepsCombinedForeignCommand(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "defenseclaw.json")
	script := filepath.Join(root, "hooks", "copilot-hook.sh")
	foreign := map[string]interface{}{
		"type":       "command",
		"bash":       copilotHookInvocationCommandForEvent("linux", "preToolUse", script),
		"powershell": "Write-Output operator",
	}
	seed := func() []byte {
		t.Helper()
		cfg := map[string]interface{}{"hooks": map[string]interface{}{"extraEvent": []interface{}{foreign}}}
		if err := writeJSONObject(path, cfg); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := seed()
	if err := patchCopilotHooksForOS(path, script, []string{"preToolUse"}, "linux"); err == nil {
		t.Fatal("Setup silently removed a combined operator command")
	}
	if got, _ := os.ReadFile(path); !reflect.DeepEqual(got, before) {
		t.Fatalf("refused Setup changed the file: %s", got)
	}
	before = seed()
	if err := removeCopilotHookReferences(path, script); err == nil {
		t.Fatal("teardown silently removed a combined operator command")
	}
	if got, _ := os.ReadFile(path); !reflect.DeepEqual(got, before) {
		t.Fatalf("refused teardown changed the file: %s", got)
	}
}

func TestCopilotCleanupKeepsOperatorCommandMentioningHookPath(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "defenseclaw.json")
	script := filepath.Join(root, "hooks", "copilot-hook.sh")
	operator := map[string]interface{}{"type": "command", "bash": "printf '%s\\n' '" + script + "' >> /opt/operator/audit.log"}
	seed := func() {
		t.Helper()
		cfg := map[string]interface{}{"hooks": map[string]interface{}{"extraEvent": []interface{}{
			copilotHookRegistration("linux", "preToolUse", script), operator,
		}}}
		if err := writeJSONObject(path, cfg); err != nil {
			t.Fatal(err)
		}
	}
	check := func(phase string) {
		t.Helper()
		hooks := decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})
		if !sameHookJSON(hooks["extraEvent"], []interface{}{operator}) {
			t.Fatalf("%s removed operator command mentioning hook path: %v", phase, hooks["extraEvent"])
		}
	}
	seed()
	if err := patchCopilotHooksForOS(path, script, []string{"preToolUse"}, "linux"); err != nil {
		t.Fatal(err)
	}
	check("setup")
	seed()
	if err := removeCopilotHookReferences(path, script); err != nil {
		t.Fatal(err)
	}
	check("teardown")
}

func TestCopilotUnexpectedCleanupKeepsLiveOperatorLookalike(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "defenseclaw.json")
			current := filepath.Join(root, "current", "copilot-hook.sh")
			operator := filepath.Join(root, "operator", "copilot-hook.sh")
			field := "bash"
			if goos == "windows" {
				current = windowsCopilotPowerShellAdapterCommand(current)
				operator = windowsCopilotPowerShellAdapterCommand(operator)
				field = "powershell"
			}
			operatorPath := filepath.Join(root, "operator", "copilot-hook.sh")
			if goos == "windows" {
				operatorPath = filepath.Join(root, "operator", "copilot-hook.ps1")
			}
			if err := os.MkdirAll(filepath.Dir(operatorPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(operatorPath, []byte("operator hook\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			foreign := map[string]interface{}{"type": "command", field: copilotHookInvocationCommandForEvent(goos, "preToolUse", operator)}
			seed := func() {
				t.Helper()
				doc := map[string]interface{}{"hooks": map[string]interface{}{
					"unexpectedEvent": []interface{}{
						map[string]interface{}{"type": "command", field: copilotHookInvocationCommandForEvent(goos, "preToolUse", current)},
						foreign,
					},
				}}
				if err := writeJSONObject(path, doc); err != nil {
					t.Fatal(err)
				}
			}
			check := func(phase string) {
				t.Helper()
				hooks := decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})
				if !sameHookJSON(hooks["unexpectedEvent"], []interface{}{foreign}) {
					t.Fatalf("%s removed the live operator handler: %v", phase, hooks["unexpectedEvent"])
				}
			}
			seed()
			if err := patchCopilotHooksForOS(path, current, []string{"preToolUse"}, goos); err != nil {
				t.Fatal(err)
			}
			check("Setup")
			seed()
			if err := removeCopilotHookReferences(path, current); err != nil {
				t.Fatal(err)
			}
			check("teardown")
		})
	}
}
