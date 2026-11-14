// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func windowsBoundsFindings(t *testing.T, pack, tool, command, home string, strict bool) []RuleFinding {
	t.Helper()
	installToolCallCorpusPackDirConnector(t, "windows-bounds", filepath.Join(guardrailPoliciesRoot(t), pack))
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	return dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: tool, Args: args, CWD: home + `\work`, ActiveHome: home},
		LegacyText: string(args), Connector: "windows-bounds", EnforcementCapable: true, StrictPolicy: strict,
	})
}

func windowsBoundsHasLimit(findings []RuleFinding) bool {
	return slices.ContainsFunc(findings, func(f RuleFinding) bool { return canonicalTrustedRuleID(f.RuleID) == evaluationLimitRuleID })
}

// windowsEncodedCommand is the -EncodedCommand value of a script: base64 of its
// UTF-16LE text.
func windowsEncodedCommand(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 0, 2*len(units))
	for _, unit := range units {
		raw = append(raw, byte(unit), byte(unit>>8))
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// windowsFixtureCommand is the command of a toolcall corpus fixture by id.
func windowsFixtureCommand(t *testing.T, id string) (command, rule string) {
	t.Helper()
	for _, row := range readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl") {
		if row.ID == id {
			return row.Command, row.RuleID
		}
	}
	t.Fatalf("no toolcall fixture %s", id)
	return "", ""
}

// TestWindowsCallPastTheTokenizerWordLimitIsTruncated (rel-1-0-10:GAP-0345): a
// PowerShell call with one word past the tokenizer's word limit is read as far
// as it goes and judged as unknown at the pack's unknown tier at least; it is
// never a clean allow.
func TestWindowsCallPastTheTokenizerWordLimitIsTruncated(t *testing.T) {
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			big := `Set-Content -Path C:\Users\alice\work\a.txt -Value '` + strings.Repeat("x", 6<<10) + `'`
			findings := windowsBoundsFindings(t, pack, "PowerShell", big, `C:\Users\alice`, pack == "strict")
			if !windowsBoundsHasLimit(findings) {
				t.Fatalf("a call past the word limit has no evaluation-limit finding: %v", FindingStrings(findings))
			}
			small := strings.Replace(big, strings.Repeat("x", 6<<10), "x", 1)
			if windowsBoundsHasLimit(windowsBoundsFindings(t, pack, "PowerShell", small, `C:\Users\alice`, pack == "strict")) {
				t.Fatal("a small call is truncated")
			}
		})
	}
}

// TestWindowsEncodedScriptPastTheWordLimitIsStillRead (GAP-0345, GAP-0344): the
// launcher's decoded script is read by the additive twin even when the call's
// own encoded word is past the tokenizer's limit, and what it names decides.
func TestWindowsEncodedScriptPastTheWordLimitIsStillRead(t *testing.T) {
	command, rule := windowsFixtureCommand(t, "windows-disable-multiple-defender-registry-controls")
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			script := command + "\n# " + strings.Repeat("x", 1500)
			call := "powershell -NoProfile -EncodedCommand " + windowsEncodedCommand(script)
			if len(windowsEncodedCommand(script)) <= 4096 {
				t.Fatal("the encoded word is not past the word limit")
			}
			findings := windowsBoundsFindings(t, pack, "PowerShell", call, `C:\Users\alice`, pack == "strict")
			if !slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == rule }) && !windowsBoundsHasLimit(findings) {
				t.Fatalf("the encoded script is neither read (%s) nor truncated: %v", rule, FindingStrings(findings))
			}
		})
	}
}

// TestWindowsWrapperDepthIsOneBudgetAndTruncated (GAP-0344, GAP-0346): a script
// inside more call blocks than the wrapper depth is truncated, not allowed; the
// depth is one budget of the call however many twins it takes.
func TestWindowsWrapperDepthIsOneBudgetAndTruncated(t *testing.T) {
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			wrap := func(layers int) string {
				return strings.Repeat("& { ", layers) + "Get-Date" + strings.Repeat(" }", layers)
			}
			within := windowsBoundsFindings(t, pack, "PowerShell", wrap(actionfacts.MaxWrapperDepth), `C:\Users\alice`, pack == "strict")
			if windowsBoundsHasLimit(within) {
				t.Fatalf("a script within the wrapper depth is truncated: %v", FindingStrings(within))
			}
			for _, layers := range []int{actionfacts.MaxWrapperDepth + 1, 3 * actionfacts.MaxWrapperDepth, 64} {
				findings := windowsBoundsFindings(t, pack, "PowerShell", wrap(layers), `C:\Users\alice`, pack == "strict")
				if !windowsBoundsHasLimit(findings) {
					t.Fatalf("%d layers are not truncated: %v", layers, FindingStrings(findings))
				}
			}
		})
	}
}

// TestWindowsProfilePathWithASpaceIsAProtectedKeyFile (GAP-0349): the
// authorized_keys file of a profile whose folder name holds a space is the
// protected file, in every spelling a call can name it.
func TestWindowsProfilePathWithASpaceIsAProtectedKeyFile(t *testing.T) {
	home := `C:\Users\alice sp`
	key := home + `\.ssh\authorized_keys`
	for _, test := range []struct{ name, tool, command string }{
		{"native", "PowerShell", `Add-Content -Path "` + key + `" -Value k`},
		{"redirect", "PowerShell", `echo k >> "` + key + `"`},
		{"launcher in a POSIX tool", "Bash", `powershell -NoProfile -Command Add-Content -Path "` + key + `" -Value k`},
		{"foreign profile with a space, launcher words in a POSIX tool", "Bash", `powershell -NoProfile -Command Add-Content -Path "C:\Users\other sp\.ssh\authorized_keys" -Value k`},
		{"launcher with quoted body", "PowerShell", `powershell -NoProfile -Command "Add-Content -Path '` + key + `' -Value k"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			findings := windowsBoundsFindings(t, "default", test.tool, test.command, home, false)
			if !slices.ContainsFunc(findings, func(f RuleFinding) bool {
				return f.RuleID == "persistence.ssh_authorized_keys_command" || f.RuleID == "PATH-SSH-DIR"
			}) {
				t.Fatalf("no key-file finding: %v", FindingStrings(findings))
			}
		})
	}
}
