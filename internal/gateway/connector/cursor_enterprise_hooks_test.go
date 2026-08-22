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

package connector

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const (
	testWindowsCursorAdapter = `C:\ProgramData\Cursor\DefenseClaw\cursor-hook.ps1`
	testWindowsHookBinary    = `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`
)

func TestRenderWindowsCursorEnterpriseAdapterUsesSharedLauncherStdinAndClosedMode(t *testing.T) {
	rendered, err := RenderWindowsCursorEnterpriseAdapter(testWindowsHookBinary, "closed")
	if err != nil {
		t.Fatalf("RenderWindowsCursorEnterpriseAdapter: %v", err)
	}
	text := string(rendered)
	for _, marker := range []string{
		`$startInfo.FileName = $hook`,
		`$startInfo.Arguments = 'hook --connector cursor --enterprise-managed'`,
		`$startInfo.RedirectStandardInput = $true`,
		`$process.StandardInput.BaseStream`,
		`$stdinStream.WriteAsync($payloadBytes, 0, $payloadBytes.Length)`,
		`[void]$stdinTask.GetAwaiter().GetResult()`,
		`$deadline = [System.Diagnostics.Stopwatch]::StartNew()`,
		`$remainingMs = $timeoutMs - [int]$deadline.ElapsedMilliseconds`,
		`{"continue":false,"permission":"deny"`,
		`$exitCode = 2`,
		`[Console]::Out.Flush()`,
		`[Console]::Error.Flush()`,
		`[System.Environment]::Exit([int]$exitCode)`,
	} {
		if !strings.Contains(text, marker) {
			t.Errorf("managed Cursor adapter missing %q:\n%s", marker, text)
		}
	}
	for _, forbidden := range []string{"--input-file", ".cursor-input-", "[IO.File]::Open", testWindowsCursorAdapter} {
		if strings.Contains(text, forbidden) {
			t.Errorf("managed Cursor adapter unexpectedly contains %q:\n%s", forbidden, text)
		}
	}
	if strings.Contains(text, `{"continue":true}`) {
		t.Fatalf("managed Cursor adapter contains a fail-open response:\n%s", text)
	}
}

func TestRenderCursorAdapterFailsOpenOnlyWhenExplicitlyConfigured(t *testing.T) {
	openAdapter, err := renderWindowsCursorAdapter(testWindowsHookBinary, "open", false, 1_000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(openAdapter, []byte(`{"continue":true}`)) ||
		bytes.Contains(openAdapter, []byte(`{"continue":false,"permission":"deny"`)) {
		t.Fatalf("explicit-open adapter has wrong fallback:\n%s", openAdapter)
	}
	if bytes.Contains(openAdapter, []byte("--enterprise-managed")) {
		t.Fatalf("unmanaged adapter contains enterprise flag:\n%s", openAdapter)
	}

	closedAdapter, err := renderWindowsCursorAdapter(testWindowsHookBinary, "typo", false, 1_000)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(closedAdapter, []byte(`{"continue":true}`)) ||
		!bytes.Contains(closedAdapter, []byte(`{"continue":false,"permission":"deny"`)) {
		t.Fatalf("invalid fail mode did not collapse closed:\n%s", closedAdapter)
	}

	if _, err := RenderWindowsCursorEnterpriseAdapter(testWindowsHookBinary, "open"); err == nil {
		t.Fatal("enterprise adapter accepted fail-open mode")
	}
}

func TestWindowsCursorEnterprisePathValidation(t *testing.T) {
	valid := []string{
		testWindowsCursorAdapter,
		`d:\Cisco Files\O'Brien\cursor-hook.ps1`,
	}
	for _, path := range valid {
		if err := validateAbsoluteLocalWindowsPath("test", path); err != nil {
			t.Errorf("valid path %q rejected: %v", path, err)
		}
	}
	invalid := []string{
		`cursor-hook.ps1`,
		`C:cursor-hook.ps1`,
		`C:/ProgramData/Cursor/cursor-hook.ps1`,
		`C:\ProgramData/Cursor\cursor-hook.ps1`,
		`\\server\share\cursor-hook.ps1`,
		`\\?\C:\ProgramData\Cursor\cursor-hook.ps1`,
		`C:\ProgramData\..\Windows\cursor-hook.ps1`,
		`C:\ProgramData\\Cursor\cursor-hook.ps1`,
		`C:\ProgramData\Cursor\cursor-hook.ps1:payload`,
		`C:\ProgramData\Cursor\CON\cursor-hook.ps1`,
		`C:\ProgramData\Cursor\nul.txt`,
		`C:\ProgramData\Cursor\COM1.ps1`,
		`C:\ProgramData\Cursor\COM1 .ps1`,
		`C:\ProgramData\Cursor\lpt9\cursor-hook.ps1`,
		`C:\ProgramData\Cursor\COM².log`,
		`C:\ProgramData\Cursor\folder.\cursor-hook.ps1`,
		`C:\ProgramData\Cursor\folder \cursor-hook.ps1`,
		"C:\\ProgramData\\Cursor\\cursor-hook.ps1\n",
	}
	for _, path := range invalid {
		if err := validateAbsoluteLocalWindowsPath("test", path); err == nil {
			t.Errorf("invalid path %q accepted", path)
		}
	}
}

func TestMergeVerifyAndRemoveWindowsCursorEnterpriseHooks(t *testing.T) {
	command, err := windowsCursorEnterpriseHookCommand(testWindowsCursorAdapter)
	if err != nil {
		t.Fatal(err)
	}
	foreignCommand := `& 'C:\ProgramData\Operator\cursor-hook.ps1'`
	nearMatch := command + " --operator-owned"
	seed := []byte(`{
  "version": 1,
  "operatorSetting": {"ratio": 1.20, "enabled": true},
  "hooks": {
    "beforeShellExecution": [
      {"type":"command","command":"` + jsonEscapeForTest(t, foreignCommand) + `","timeout":9000,"operator":{"x":1}},
      {"type":"command","command":"` + jsonEscapeForTest(t, command) + `","timeout":1,"failClosed":false},
      {"type":"command","command":"` + jsonEscapeForTest(t, nearMatch) + `","timeout":7000}
    ],
    "operatorEvent": [
      {"type":"command","command":"` + jsonEscapeForTest(t, foreignCommand) + `","failClosed":false},
      {"type":"command","command":"` + jsonEscapeForTest(t, command) + `","failClosed":true}
    ]
  }
}`)

	merged, err := MergeWindowsCursorEnterpriseHooks(seed, testWindowsCursorAdapter, "closed")
	if err != nil {
		t.Fatalf("MergeWindowsCursorEnterpriseHooks: %v", err)
	}
	if err := VerifyWindowsCursorEnterpriseHooks(merged, testWindowsCursorAdapter, "closed"); err != nil {
		t.Fatalf("VerifyWindowsCursorEnterpriseHooks: %v\n%s", err, merged)
	}
	mergedAgain, err := MergeWindowsCursorEnterpriseHooks(merged, testWindowsCursorAdapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(merged, mergedAgain) {
		t.Fatalf("enterprise hook merge is not byte-idempotent\nfirst:\n%s\nsecond:\n%s", merged, mergedAgain)
	}

	cfg, err := decodeCursorHooksJSON(merged)
	if err != nil {
		t.Fatal(err)
	}
	operatorSetting := cfg["operatorSetting"].(map[string]interface{})
	if ratio := operatorSetting["ratio"].(json.Number).String(); ratio != "1.20" {
		t.Fatalf("unrelated JSON number changed from 1.20 to %s", ratio)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	before := hooks["beforeShellExecution"].([]interface{})
	if len(before) != 3 || cursorHookCommand(before[0]) != foreignCommand || cursorHookCommand(before[1]) != nearMatch || cursorHookCommand(before[2]) != command {
		t.Fatalf("foreign ordering/entries changed: %#v", before)
	}
	ownedEntry := before[2].(map[string]interface{})
	if timeout, ok := ownedEntry["timeout"].(json.Number); !ok || timeout.String() != "30" {
		t.Fatalf("Cursor enterprise timeout = %#v, want 30 seconds", ownedEntry["timeout"])
	}
	if _, exists := hooks["operatorEvent"]; !exists {
		t.Fatal("unrelated event was removed during merge")
	}
	operatorEntries := hooks["operatorEvent"].([]interface{})
	if len(operatorEntries) != 1 || cursorHookCommand(operatorEntries[0]) != foreignCommand {
		t.Fatalf("unexpected exact managed command was not pruned from unrelated event: %#v", operatorEntries)
	}

	removed, err := RemoveWindowsCursorEnterpriseHooks(merged, testWindowsCursorAdapter)
	if err != nil {
		t.Fatalf("RemoveWindowsCursorEnterpriseHooks: %v", err)
	}
	removedCfg, err := decodeCursorHooksJSON(removed)
	if err != nil {
		t.Fatal(err)
	}
	removedHooks := removedCfg["hooks"].(map[string]interface{})
	for event, raw := range removedHooks {
		entries, ok := cursorHookEntryList(raw)
		if !ok {
			continue
		}
		for _, entry := range entries {
			if cursorHookCommand(entry) == command {
				t.Fatalf("managed command remains under %s: %#v", event, entry)
			}
		}
	}
	before = removedHooks["beforeShellExecution"].([]interface{})
	if len(before) != 2 || cursorHookCommand(before[0]) != foreignCommand || cursorHookCommand(before[1]) != nearMatch {
		t.Fatalf("remove claimed unrelated hooks: %#v", before)
	}
	removedAgain, err := RemoveWindowsCursorEnterpriseHooks(removed, testWindowsCursorAdapter)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(removed, removedAgain) {
		t.Fatal("no-op remove did not return the original bytes")
	}
}

func TestWindowsCursorEnterpriseHooksRejectMalformedOrDriftedContracts(t *testing.T) {
	for name, raw := range map[string][]byte{
		"multiple_values": []byte(`{} {}`),
		"wrong_version":   []byte(`{"version":2,"hooks":{}}`),
		"hooks_array":     []byte(`{"version":1,"hooks":[]}`),
		"managed_event_object": []byte(`{
          "version":1,
          "hooks":{"beforeShellExecution":{"command":"foreign"}}
        }`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := MergeWindowsCursorEnterpriseHooks(raw, testWindowsCursorAdapter, "closed"); err == nil {
				t.Fatal("malformed contract was accepted")
			}
		})
	}
	if _, err := MergeWindowsCursorEnterpriseHooks(nil, testWindowsCursorAdapter, "open"); err == nil {
		t.Fatal("enterprise hook merge accepted fail-open mode")
	}
	if _, err := MergeWindowsCursorEnterpriseHooks(
		bytes.Repeat([]byte(" "), windowsCursorEnterpriseHooksJSONMax+1),
		testWindowsCursorAdapter,
		"closed",
	); err == nil {
		t.Fatal("enterprise hook merge accepted an oversized config")
	}

	merged, err := MergeWindowsCursorEnterpriseHooks(nil, testWindowsCursorAdapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(merged))
	decoder.UseNumber()
	if err := decoder.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	entries := hooks["preToolUse"].([]interface{})
	entry := entries[0].(map[string]interface{})
	entry["failClosed"] = false
	drifted, err := encodeCursorHooksJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWindowsCursorEnterpriseHooks(drifted, testWindowsCursorAdapter, "closed"); err == nil {
		t.Fatal("drifted enterprise hook entry verified")
	}
}

func TestWindowsCursorEnterpriseHooksSemanticHelpers(t *testing.T) {
	left := []byte(`{"version":1,"hooks":{},"operator":{"ratio":1.20,"list":[true,null]}}`)
	right := []byte("{\n  \"operator\": {\"list\":[true,null],\"ratio\":1.2},\n  \"hooks\": {},\n  \"version\": 1.0\n}\n")
	if !WindowsCursorEnterpriseHooksSemanticallyEqual(left, right) {
		t.Fatal("equivalent hooks JSON did not compare semantically equal")
	}
	if WindowsCursorEnterpriseHooksSemanticallyEqual(left, []byte(`{"version":1,"hooks":{"x":[]}}`)) {
		t.Fatal("different hooks JSON compared equal")
	}
	if WindowsCursorEnterpriseHooksSemanticallyEqual([]byte(`{`), []byte(`{`)) {
		t.Fatal("invalid hooks JSON compared equal")
	}
	if !WindowsCursorEnterpriseHooksEmpty([]byte(`{"hooks":{},"version":1}`)) {
		t.Fatal("canonical empty hooks contract was not recognized")
	}
	for _, nonEmpty := range [][]byte{
		nil,
		[]byte(`{}`),
		[]byte(`{"version":1,"hooks":null}`),
		[]byte(`{"version":1,"hooks":{"event":[]}}`),
		[]byte(`{"version":1,"hooks":{},"operator":true}`),
	} {
		if WindowsCursorEnterpriseHooksEmpty(nonEmpty) {
			t.Fatalf("non-empty/invalid contract was recognized as empty: %s", nonEmpty)
		}
	}
}

func TestWindowsCursorEnterpriseOwnedRemainderRestoresMinimalOriginal(t *testing.T) {
	for name, original := range map[string][]byte{
		"empty_file":          nil,
		"empty_object":        []byte(`{}`),
		"version_only":        []byte(`{"version":1}`),
		"empty_hooks":         []byte(`{"version":1,"hooks":{}}`),
		"empty_managed_event": []byte(`{"version":1,"hooks":{"preToolUse":[]}}`),
		"null_managed_event":  []byte(`{"version":1,"hooks":{"preToolUse":null}}`),
	} {
		t.Run(name, func(t *testing.T) {
			managed, err := MergeWindowsCursorEnterpriseHooks(
				original,
				testWindowsCursorAdapter,
				"closed",
			)
			if err != nil {
				t.Fatal(err)
			}
			cleaned, err := RemoveWindowsCursorEnterpriseHooks(managed, testWindowsCursorAdapter)
			if err != nil {
				t.Fatal(err)
			}
			if !WindowsCursorEnterpriseHooksOwnedRemainderEqual(cleaned, original) {
				t.Fatalf("owned remainder did not match original\ncleaned: %s\noriginal: %s", cleaned, original)
			}
		})
	}

	foreign := []byte(`{"version":1,"hooks":{"preToolUse":[{"type":"command","command":"operator"}]}}`)
	if WindowsCursorEnterpriseHooksOwnedRemainderEqual(
		[]byte(`{"version":1,"hooks":{}}`),
		foreign,
	) {
		t.Fatal("non-empty foreign hook was treated as owned scaffolding")
	}
}

func TestIsBuiltinCursorConnector(t *testing.T) {
	if !IsBuiltinCursorConnector(NewCursorConnector()) {
		t.Fatal("built-in Cursor connector was not recognized")
	}
	if IsBuiltinCursorConnector(NewWindsurfConnector()) || IsBuiltinCursorConnector(nil) {
		t.Fatal("non-Cursor connector was recognized as built-in Cursor")
	}
}

func jsonEscapeForTest(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded[1 : len(encoded)-1])
}
