// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"strings"
	"testing"
)

// g072 review 2 S3: PowerShell reads U+2018 to U+201B as single quotes, so a
// per-user hook under a profile like C:\Users\O’Brien ended its literal
// early and the registered command did not parse; the hook fell to its fail
// mode. Every hook-command builder doubles the typographic quote now, the
// ownership readers read it back, and the pre-1.0.9 render stays owned so
// setup rewrites it and teardown removes it.
func TestWindowsHookCommandsQuoteATypographicQuoteInTheProfilePath(t *testing.T) {
	// Every typographic single quote PowerShell reads (g072 review 3 N2).
	for _, quote := range []string{"\u2018", "\u2019", "\u201a", "\u201b"} {
		t.Run(fmt.Sprintf("U+%04X", []rune(quote)[0]), func(t *testing.T) {
			hook := `C:\Users\O` + quote + `Brien\AppData\Local\DefenseClaw\bin\defenseclaw-hook.exe`
			quoted := `'C:\Users\O` + quote + quote + `Brien\AppData\Local\DefenseClaw\bin\defenseclaw-hook.exe'`
			restore := PinNativeHookExecutableForTest(hook)
			t.Cleanup(restore)

			if got := powershellQuoteLiteral(hook); got != quoted {
				t.Fatalf("powershellQuoteLiteral = %s, want %s", got, quoted)
			}
			if got := PowerShellQuoteLiteral(hook); got != quoted {
				t.Fatalf("PowerShellQuoteLiteral = %s, want %s", got, quoted)
			}
			if got := powershellLiteralBody(hook); "'"+got+"'" != quoted {
				t.Fatalf("HookBinaryPS body = %s", got)
			}
			prefix := windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand "
			scriptOf := func(command string) string {
				if encoded, ok := strings.CutPrefix(command, prefix); ok {
					script, decoded := powershellDecodedCommand(encoded)
					if !decoded {
						t.Fatalf("undecodable bridge %s", command)
					}
					return script
				}
				return command
			}
			for name, command := range map[string]string{
				"copilot":               windowsCopilotPowerShellHookCommandForBinary(hook),
				"legacy native":         legacyWindowsNativePowerShellHookCommandForBinary("codex", hook),
				"legacy unqualified":    legacyUnqualifiedWindowsNativePowerShellHookCommandForBinary("codex", hook),
				"codex managed":         legacyCallOperatorWindowsCodexManagedHookCommand(hook),
				"guarded copilot guard": CopilotRemovedDeploymentGuardPowerShell(hook),
			} {
				if !strings.Contains(scriptOf(command), quoted) {
					t.Errorf("%s does not quote the typographic quote: %s", name, scriptOf(command))
				}
			}
			bridge := windowsNativePowerShellHookCommandForBinary("codex", hook)
			script := scriptOf(bridge)
			if !strings.HasPrefix(bridge, prefix) || !strings.Contains(script, quoted) {
				t.Fatalf("encoded bridge does not quote the typographic quote: %s", script)
			}

			// The readers: the generic native form, the Claude Code legacy form.
			direct := "& " + quoted + " " + nativeHookFlag + "codex"
			if !isNativeHookCommand(direct) {
				t.Errorf("isNativeHookCommand(%s) = false", direct)
			}
			if executable, ok := parseLegacyClaudeCodeNativeHookCommand("& " + quoted + " " + nativeHookFlag + "claudecode"); !ok || executable != hook {
				t.Errorf("parseLegacyClaudeCodeNativeHookCommand = %q, %t, want %q", executable, ok, hook)
			}

			// The pre-1.0.9 renders, with the typographic quote not doubled, stay
			// owned: the direct form through the reader, the encoded bridge exactly.
			before := strings.ReplaceAll(direct, quote+quote, quote)
			if !isNativeHookCommand(before) {
				t.Errorf("the pre-1.0.9 direct hook is not owned: %s", before)
			}
			oldBridge := prefix + powershellEncodedCommand(strings.ReplaceAll(script, quote+quote, quote))
			exact := nativeHookExactCommands([]string{hook})
			if _, ok := exact[bridge]; !ok {
				t.Error("the current bridge is not in the exact set")
			}
			if _, ok := exact[oldBridge]; !ok || !isNativeHookCommand(oldBridge) {
				t.Error("the pre-1.0.9 bridge is not owned")
			}
			if old, ok := preTypographicQuoteHookCommand(windowsNativePowerShellHookCommandForBinary("codex", `C:\Users\dc-user\defenseclaw-hook.exe`)); ok {
				t.Errorf("a path without a typographic quote has an earlier form: %s", old)
			}
		})
	}
}
