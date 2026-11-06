// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// powershellQuoteGolden is the file the Python readers' cross-language test
// (cli/tests/test_powershell_quote_golden.py) reads: the per-user Windows hook
// commands this package renders for a profile path holding each PowerShell
// single quote. Go writes it, Python reads it, so the two cannot drift apart
// (g072 review 3 M3).
var powershellQuoteGolden = filepath.Join("..", "..", "..", "testdata", "powershell_quotes", "windows_hook_commands.json")

type powershellQuoteGoldenRow struct {
	Quote                string `json:"quote"`
	Hook                 string `json:"hook"`
	HookLiteral          string `json:"hook_literal"`
	CopilotAdapter       string `json:"copilot_adapter"`
	CopilotEvent         string `json:"copilot_event"`
	CopilotCommand       string `json:"copilot_command"`
	CopilotAdapterHook   string `json:"copilot_adapter_hook_line"`
	CursorAdapter        string `json:"cursor_adapter"`
	CursorCommand        string `json:"cursor_command"`
	CodexBridge          string `json:"codex_bridge"`
	CodexBridgeBefore109 string `json:"codex_bridge_before_1_0_9"`
	CodexDirect          string `json:"codex_direct"`
	CodexDirectBefore109 string `json:"codex_direct_before_1_0_9"`
	CopilotCommandBefore string `json:"copilot_command_before_1_0_9"`
	CursorCommandBefore  string `json:"cursor_command_before_1_0_9"`
}

// TestWindowsHookCommandsMatchThePythonReadersGolden renders the golden rows
// and compares them with the checked-in file; DEFENSECLAW_UPDATE_GOLDEN=1
// rewrites it. Every PowerShell single quote has a row: the apostrophe and
// U+2018 to U+201B.
func TestWindowsHookCommandsMatchThePythonReadersGolden(t *testing.T) {
	savedSystem := windowsSystemDirectory
	windowsSystemDirectory = func() string { return `C:\Windows\System32` }
	t.Cleanup(func() { windowsSystemDirectory = savedSystem })

	var rows []powershellQuoteGoldenRow
	for _, quote := range []rune{'\'', '\u2018', '\u2019', '\u201a', '\u201b'} {
		profile := `C:\Users\O` + string(quote) + `Brien`
		hook := profile + `\AppData\Local\DefenseClaw\bin\defenseclaw-hook.exe`
		hooks := profile + `\.defenseclaw\hooks\`
		restore := PinNativeHookExecutableForTest(hook)
		adapterScript, err := renderHookTemplate("copilot-hook.ps1", templateData{
			HookBinaryPS:         powershellLiteralBody(defenseclawHookBinary()),
			CopilotHookTimeoutMS: copilotWindowsHookAdapterTimeoutMS,
		})
		if err != nil {
			restore()
			t.Fatal(err)
		}
		hookLine := ""
		for _, line := range strings.Split(strings.ReplaceAll(string(adapterScript), "\r\n", "\n"), "\n") {
			if strings.HasPrefix(line, "$hook = '") {
				hookLine = line
			}
		}
		row := powershellQuoteGoldenRow{
			Quote:              fmt.Sprintf("U+%04X", quote),
			Hook:               hook,
			HookLiteral:        PowerShellQuoteLiteral(hook),
			CopilotAdapter:     hooks + "copilot-hook.ps1",
			CopilotEvent:       "preToolUse",
			CopilotCommand:     copilotHookInvocationCommandForEvent("windows", "preToolUse", hooks+"copilot-hook.sh"),
			CopilotAdapterHook: hookLine,
			CursorAdapter:      hooks + "cursor-hook.ps1",
			CursorCommand:      hookInvocationCommandFor("windows", "cursor", hooks+"cursor-hook.sh"),
			CodexBridge:        hookInvocationCommandFor("windows", "codex", ""),
			CodexDirect:        "& " + PowerShellQuoteLiteral(hook) + " " + nativeHookFlag + "codex",
		}
		row.CodexBridgeBefore109, _ = preTypographicQuoteHookCommand(row.CodexBridge)
		row.CodexDirectBefore109, _ = preTypographicQuoteHookCommand(row.CodexDirect)
		row.CopilotCommandBefore, _ = preTypographicQuoteHookCommand(row.CopilotCommand)
		row.CursorCommandBefore, _ = preTypographicQuoteHookCommand(row.CursorCommand)
		if hookLine == "" {
			restore()
			t.Fatalf("%s: the Copilot adapter has no $hook line", row.Quote)
		}
		if _, ok := nativeHookExactCommands([]string{hook})[row.CodexBridge]; !ok || !isNativeHookCommand(row.CodexDirect) {
			t.Errorf("%s: the gateway does not own its own render", row.Quote)
		}
		if quote != '\'' {
			if row.CodexBridgeBefore109 == "" || row.CopilotCommandBefore == "" || row.CursorCommandBefore == "" {
				t.Errorf("%s: no pre-1.0.9 form", row.Quote)
			}
			if _, ok := nativeHookExactCommands([]string{hook})[row.CodexBridgeBefore109]; !ok {
				t.Errorf("%s: the pre-1.0.9 bridge is not owned", row.Quote)
			}
			// Cursor's exact-string rail owns its pre-1.0.9 adapter command
			// too (g072 review 4 M1).
			cursorBefore := map[string]interface{}{"type": "command", "command": row.CursorCommandBefore}
			if !newCursorHookCommandMatcher(cursorManagedHookCommands(row.CursorCommand, hooks+"cursor-hook.sh")).matches(cursorBefore) {
				t.Errorf("%s: setup does not own the pre-1.0.9 Cursor command", row.Quote)
			}
		}
		restore()
		rows = append(rows, row)
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"about": "Written by TestWindowsHookCommandsMatchThePythonReadersGolden (internal/gateway/connector); " +
			"read by cli/tests/test_powershell_quote_golden.py. Regenerate with DEFENSECLAW_UPDATE_GOLDEN=1.",
		"rows": rows,
	}); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(powershellQuoteGolden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(powershellQuoteGolden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(powershellQuoteGolden)
	if err != nil {
		t.Fatalf("missing golden (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), buf.Bytes()) {
		t.Fatalf("%s drifted from the Go renders (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1, then run the Python test):\n--- want\n%s\n--- got\n%s", powershellQuoteGolden, want, buf.Bytes())
	}
}
