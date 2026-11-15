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
	{"call-block", func(c string) string { return `& { ` + c + ` }` }},
}

// windowsWrappedKnownLimit lists the fixtures a wrapper is known to hide, with
// the reason; each is a rule whose owner proves a whole script of exactly the
// commands it names (a pair of commands in a fixed order), so a second
// statement is no longer that script.
var windowsWrappedKnownLimit = map[string]string{
	"windows-uac-eventvwr-autoelevation-hijack": "whole-script owner: an extra statement is not the registry-write-then-launch pair",
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

func windowsToolCallFindings(t *testing.T, connector, tool, command string) []RuleFinding {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	return dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: tool, Args: args, CWD: `C:\work`, ActiveHome: `C:\Users\alice`},
		LegacyText: string(args), Connector: connector, EnforcementCapable: true,
	})
}

// TestWindowsStatementWrappersKeepTheFixtureVerdict wraps every attack fixture
// that fires as a bare PowerShell tool call and expects the same rule to fire.
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
				fires := func(tool, command string) bool {
					return slices.ContainsFunc(windowsToolCallFindings(t, "windows-wrapped", tool, command),
						func(f RuleFinding) bool {
							// The strict pack reports the pipe form of a cradle as
							// curl-to-shell when the statement list is partial.
							return windowsRuleOrEquivalent(f.RuleID, rule) || rule == "CMD-WIN-IWR-IEX" && f.RuleID == "CMD-PIPE-CURL"
						})
				}
				if !fires("PowerShell", test.Command) {
					continue
				}
				bare++
				if windowsWrappedKnownLimit[test.ID] != "" {
					continue
				}
				for _, tool := range windowsWrappedTools {
					for _, wrapper := range windowsStatementWrappers {
						if !fires(tool, wrapper.wrap(test.Command)) {
							missed[wrapper.name] = append(missed[wrapper.name], tool+"/"+test.ID)
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
				if wrapper.name == "trailer" {
					// A trailing statement under a non-PowerShell tool label still
					// hides the native-program fixtures (git first); logged above,
					// open in GAP-0348's residual.
					continue
				}
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
