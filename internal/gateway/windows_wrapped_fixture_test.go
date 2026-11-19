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

package gateway

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// windowsStatementWrappers are spellings that wrap one PowerShell statement
// without changing what it does: a working-directory prefix, a trailing
// statement and a call block. A rule that fires on the statement written
// bare fires on every one of them (rel-1-0-10:GAP-0159).
var windowsStatementWrappers = []struct {
	name string
	wrap func(string) string
}{
	{"cd-prefix", func(c string) string { return `Set-Location C:\Users\alice\proj; ` + c }},
	{"trailer", func(c string) string { return c + ` ; Write-Output done` }},
	// The hook's selection places this spelling in no dialect: its POSIX
	// reading is complete, so only the list without its last statement
	// reads the attack (windowsListPrefixTwinRequest, rel-1-0-10:GAP-0348).
	{"echo-trailer", func(c string) string { return c + ` ; echo done` }},
	{"call-block", func(c string) string { return `& { ` + c + ` }` }},
}

// windowsWrappedKnownLimit lists the fixtures a wrapper is known to hide, with
// the reason; each is a rule whose owner proves a whole script of exactly the
// commands it names (a pair of commands in a fixed order), so a second
// statement is no longer that script.
var windowsWrappedKnownLimit = map[string]string{
	"windows-uac-eventvwr-autoelevation-hijack": "whole-script owner: an extra statement is not the registry-write-then-launch pair",
}

// windowsWrappedKnownWrapperLimit lists the (wrapper, fixture) pairs one
// wrapper is known to hide, with the reason: rel-1-0-10:GAP-1561. The hook's
// selection places `<statement> ; echo done` in no dialect; the list-prefix
// reading (windowsListPrefixTwinRequest) reads only a POSIX list whose own
// reading is complete, and these are a native program the POSIX reading
// leaves partial or PowerShell grammar the POSIX list parser cannot read.
var windowsWrappedKnownWrapperLimit = map[string]string{
	"echo-trailer/windows-procdump-lsass":                  "GAP-1561: own POSIX reading partial",
	"echo-trailer/windows-usn-journal-delete-powershell":   "GAP-1561: own POSIX reading partial",
	"echo-trailer/windows-recursive-everyone-full-control": "GAP-1561: own POSIX reading partial",
	"echo-trailer/windows-disable-amsi-reflection":         "GAP-1561: PowerShell grammar, no POSIX list",
	"echo-trailer/windows-comsvcs-lsass":                   "GAP-1561: PowerShell grammar, no POSIX list",
}

// windowsEquivalentRules are rules that name the same action in another
// spelling: a wrapped call is detected by the rule of the shell that runs its
// text (netcat for a call block, the cmd rmdir rule for cmd /c), which is the
// same detection as the bare fixture's rule.
var windowsEquivalentRules = map[string][]string{
	"CMD-REVSHELL-BASH": {"CMD-REVSHELL-NC"},
	"CMD-RM-RF":         {"CMD-WIN-RMDIR-SQ", "CMD-WIN-REMOVE-ITEM-RF"},
}

func windowsRuleOrEquivalent(found, want string) bool {
	return found == want || slices.Contains(windowsEquivalentRules[want], found)
}

// windowsWrappedTools are the tool labels a PowerShell script reaches the hook
// under on Windows: Claude Code's PowerShell tool, and the shell tools of
// connectors whose label does not name the shell.
var windowsWrappedTools = []string{"PowerShell", "Bash", "bash", "Shell"}

// windowsToolCallFindings judges a shell call as a Windows hook does: the
// agent and Codex hooks' dialect selection (withWindowsShellDialect) and the
// Windows readings, or with claudeCode Claude Code's (its Bash tool is Git
// Bash: claudeCodeWindowsShellDialect).
func windowsToolCallFindings(t *testing.T, connector, tool, command string, claudeCode bool) []RuleFinding {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	request := trustedActionRequest{
		Input:      actionfacts.Input{Tool: tool, Args: args, CWD: `C:\work`, ActiveHome: `C:\Users\alice`},
		LegacyText: string(args), Connector: connector, EnforcementCapable: true,
	}
	if claudeCode {
		request.Input.DialectHint = claudeCodeWindowsShellDialect(request.Input)
		request.windowsDialectReadings = true
	} else {
		withWindowsShellDialect(&request, true)
	}
	return dispatchTrustedAction(t.Context(), request)
}

// TestWindowsStatementWrappersKeepTheFixtureVerdict wraps every attack fixture
// that fires as a bare PowerShell tool call and expects the same rule to fire
// under every shell tool label of the Windows hooks. Claude Code's Bash tool is
// Git Bash, a POSIX shell: there a wrapped fixture must fire wherever the same
// fixture fires bare on that tool.
func TestWindowsStatementWrappersKeepTheFixtureVerdict(t *testing.T) {
	cases := readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl")
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusPackDirConnector(t, "windows-wrapped", filepath.Join(guardrailPoliciesRoot(t), pack))
			bare := 0
			missed := map[string][]string{}
			for _, test := range cases {
				if !test.IsAttack || test.Command == "" || len(test.OSOverrides) != 0 ||
					test.Dialect == actionfacts.DialectPOSIX || test.Dialect == actionfacts.DialectCMD {
					continue
				}
				if test.ProfilePosture == toolCallCorpusStrictOnlyPosture && pack != "strict" {
					continue
				}
				rule := test.RuleID
				if r := test.ProfileRuleIDs[pack]; r != "" {
					rule = r
				}
				fires := func(tool, command string, claudeCode bool) bool {
					return slices.ContainsFunc(windowsToolCallFindings(t, "windows-wrapped", tool, command, claudeCode),
						func(f RuleFinding) bool {
							// The strict pack reports the pipe form of a cradle as
							// curl-to-shell when the statement list is partial.
							return windowsRuleOrEquivalent(f.RuleID, rule) || rule == "CMD-WIN-IWR-IEX" && f.RuleID == "CMD-PIPE-CURL"
						})
				}
				if !fires("PowerShell", test.Command, false) {
					continue
				}
				bare++
				if windowsWrappedKnownLimit[test.ID] != "" {
					continue
				}
				for _, tool := range windowsWrappedTools {
					for _, wrapper := range windowsStatementWrappers {
						if windowsWrappedKnownWrapperLimit[wrapper.name+"/"+test.ID] != "" {
							continue
						}
						if !fires(tool, wrapper.wrap(test.Command), false) {
							missed[wrapper.name] = append(missed[wrapper.name], tool+"/"+test.ID)
						}
					}
				}
				if fires("Bash", test.Command, true) {
					for _, wrapper := range windowsStatementWrappers {
						if !fires("Bash", wrapper.wrap(test.Command), true) &&
							!hookpaths.GitBashReadsAlone(wrapper.wrap(test.Command), `C:\Users\alice`) {
							// A call Git Bash reads alone (a Windows host) is
							// placed in POSIX and keeps the POSIX reading, as
							// on Linux and macOS: rel-1-0-10:GAP-1561.
							missed[wrapper.name] = append(missed[wrapper.name], "claude-code-Bash/"+test.ID)
						}
					}
				}
			}
			if bare < 50 {
				t.Fatalf("%s: only %d fixtures fire bare; the fixture set changed", pack, bare)
			}
			for _, wrapper := range windowsStatementWrappers {
				unique := map[string]bool{}
				for _, id := range missed[wrapper.name] {
					unique[id[strings.Index(id, "/")+1:]] = true
				}
				t.Logf("%s: %s hides %d (tool, fixture) pairs over %d fixtures: %v", pack, wrapper.name, len(missed[wrapper.name]), len(unique), missed[wrapper.name])
				if len(missed[wrapper.name]) != 0 {
					t.Errorf("%s: %s hides %d fixtures that fire bare: %v", pack, wrapper.name, len(missed[wrapper.name]), missed[wrapper.name])
				}
			}
		})
	}
}

// TestWindowsCmdLauncherKeepsTheCmdFixtureVerdict: a cmd.exe fixture handed to
// a POSIX shell tool as `cmd /c <line>` (Git Bash on Windows) is read as the
// line cmd.exe runs, with its backslashes, not as POSIX words that drop them.
func TestWindowsCmdLauncherKeepsTheCmdFixtureVerdict(t *testing.T) {
	cases := readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl")
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusPackDirConnector(t, "windows-cmd-launcher", filepath.Join(guardrailPoliciesRoot(t), pack))
			fires := func(hint actionfacts.Dialect, command, rule string) bool {
				args, err := json.Marshal(map[string]string{"command": command})
				if err != nil {
					t.Fatal(err)
				}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input:      actionfacts.Input{Tool: "Bash", Args: args, CWD: `C:\work`, ActiveHome: `C:\Users\alice`, DialectHint: hint},
					LegacyText: string(args), Connector: "windows-cmd-launcher", EnforcementCapable: true,
				})
				return slices.ContainsFunc(findings, func(f RuleFinding) bool { return windowsRuleOrEquivalent(f.RuleID, rule) })
			}
			bare := 0
			for _, test := range cases {
				if !test.IsAttack || test.Command == "" || len(test.OSOverrides) != 0 || test.Dialect != actionfacts.DialectCMD ||
					test.ProfilePosture == toolCallCorpusStrictOnlyPosture && pack != "strict" {
					continue
				}
				rule := test.RuleID
				if r := test.ProfileRuleIDs[pack]; r != "" {
					rule = r
				}
				if !fires(actionfacts.DialectCMD, test.Command, rule) {
					continue
				}
				bare++
				if !fires("", "cmd /c "+test.Command, rule) {
					t.Errorf("%s: no %s finding for the fixture behind cmd /c", test.ID, rule)
				}
			}
			if bare < 25 {
				t.Fatalf("only %d cmd fixtures fire bare; the fixture set changed", bare)
			}
		})
	}
}
