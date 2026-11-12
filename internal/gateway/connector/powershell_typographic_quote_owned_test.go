// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// g072 review 4 M1: Cursor and Kiro own their hooks by exact strings, so the
// pre-1.0.9 render of a profile like C:\Users\O’Brien (the typographic quote
// not doubled) must be on those lists. Otherwise setup adds a second entry
// beside the broken one and teardown leaves it behind.
func TestCursorSetupAndTeardownOwnThePreTypographicQuoteRender(t *testing.T) {
	for _, quote := range []string{"\u2018", "\u2019", "\u201a", "\u201b"} {
		t.Run(fmt.Sprintf("U+%04X", []rune(quote)[0]), func(t *testing.T) {
			opts := SetupOpts{DataDir: `C:\Users\O` + quote + `Brien\.defenseclaw`}
			shellScript := filepath.Join(opts.DataDir, "hooks", "cursor-hook.sh")
			current := hookInvocationCommandFor("windows", "cursor", shellScript)
			before, ok := preTypographicQuoteHookCommand(current)
			if !ok || !strings.Contains(current, `O`+quote+quote+`Brien`) ||
				!strings.Contains(before, `O`+quote+`Brien`) || strings.Contains(before, quote+quote) {
				t.Fatalf("pre-1.0.9 form of %q = %q, %v", current, before, ok)
			}
			oldEntry := func() map[string]interface{} {
				return map[string]interface{}{"type": "command", "command": before, "timeout": json.Number("30"), "failClosed": true}
			}
			foreign := func() map[string]interface{} {
				return map[string]interface{}{"type": "command", "command": `& 'C:\Tools\audit.ps1'`}
			}
			fileWithOldEntries := func() map[string]interface{} {
				hooks := map[string]interface{}{}
				for _, event := range cursorHookEvents {
					hooks[event] = []interface{}{oldEntry(), foreign()}
				}
				return map[string]interface{}{"version": json.Number("1"), "hooks": hooks}
			}

			// The matcher setup uses owns the old form.
			if !newCursorHookCommandMatcher(cursorManagedHookCommands(current, shellScript)).matches(oldEntry()) {
				t.Fatalf("setup's matcher does not own the pre-1.0.9 entry %q", before)
			}

			// Setup leaves exactly one DefenseClaw entry per event, after the
			// foreign one.
			cfg := fileWithOldEntries()
			renderCursorHooks(cfg, current, shellScript, false)
			hooks := cfg["hooks"].(map[string]interface{})
			for _, event := range cursorHookEvents {
				entries, _ := hooks[event].([]interface{})
				if len(entries) != 2 {
					t.Fatalf("%s after setup: %d entries, want the foreign one and one current: %v", event, len(entries), entries)
				}
				if got := entries[0].(map[string]interface{})["command"]; got != `& 'C:\Tools\audit.ps1'` {
					t.Fatalf("%s after setup: first entry %v, want the foreign hook", event, got)
				}
				if got := entries[1].(map[string]interface{})["command"]; got != shellWord(current) {
					t.Fatalf("%s after setup: entry %v, want %q", event, got, shellWord(current))
				}
			}

			// Teardown removes the old entry and keeps the foreign one.
			pruned, _ := removeHookScriptReferences(fileWithOldEntries(), cursorOwnedHookCommands(opts)...).(map[string]interface{})
			prunedHooks, _ := pruned["hooks"].(map[string]interface{})
			for _, event := range cursorHookEvents {
				entries, _ := prunedHooks[event].([]interface{})
				if len(entries) != 1 || entries[0].(map[string]interface{})["command"] != `& 'C:\Tools\audit.ps1'` {
					t.Fatalf("%s after teardown: %v, want only the foreign hook", event, entries)
				}
			}
		})
	}
}

func TestKiroOwnsThePreTypographicQuoteRender(t *testing.T) {
	for _, quote := range []string{"\u2018", "\u2019", "\u201a", "\u201b"} {
		t.Run(fmt.Sprintf("U+%04X", []rune(quote)[0]), func(t *testing.T) {
			hook := `C:\Users\O` + quote + `Brien\AppData\Local\DefenseClaw\bin\defenseclaw-hook.exe`
			t.Cleanup(PinNativeHookExecutableForTest(hook))
			owned := kiroWindowsOwnedHookCommands()
			for _, managed := range []bool{false, true} {
				for _, surface := range []string{"", KiroHookSurfaceV3} {
					command := windowsKiroHookCommandForBinary(hook, surface, managed)
					before, ok := preTypographicQuoteHookCommand(command)
					if !ok || before == command {
						t.Fatalf("no pre-1.0.9 form of the Kiro command (surface %q, managed %v)", surface, managed)
					}
					if !strings.HasPrefix(before, windowsSystemCmdExe()+" /d /c ") || !strings.HasSuffix(before, "\nexit $LASTEXITCODE") {
						t.Fatalf("pre-1.0.9 form lost the cmd.exe wrapper: %q", before)
					}
					if !slices.Contains(owned, command) || !slices.Contains(owned, before) {
						t.Fatalf("Kiro does not own the current and pre-1.0.9 commands (surface %q, managed %v)", surface, managed)
					}
				}
			}
		})
	}
}
