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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// windowsNativeFixtureRules are the claimed Windows rules whose own fixture of
// the product tool-call suite did not fire when it arrived as a Claude Code
// PowerShell tool call (rel-1-0-10:GAP-0161): the suite hands the fixture to the
// analysis with a preset dialect and the command in Input.Command, a hook call
// carries the command in the tool arguments and a PowerShell tool name.
var windowsNativeFixtureRules = []string{
	"CMD-REVSHELL-POWERSHELL-TCP",
	"credential.windows_lsass_memory_dump",
	"defense_evasion.windows_defender_drive_root_exclusion",
	"defense_evasion.windows_defender_executable_exclusion",
	"exfil.literal_sensitive_json_upload",
	"persistence.windows_accessibility_feature_hijack",
	"secrets.cloud_secret_manager_read",
	"source.git_remote_tamper",
	"tamper.endpoint_security_product_disable",
	"tamper.windows_audit_detailed_tracking_failure_disable",
	"tamper.windows_audit_full_privilege_disable",
	"tamper.windows_audit_process_creation_success_disable",
	"tamper.windows_defender_component_disable",
}

// windowsFixtureViaCmd lists the fixtures that are cmd.exe syntax which
// PowerShell does not run as written: copy is Copy-Item there and /Y is no
// parameter of it, so the PowerShell tool reaches the fixture as cmd /c <line>
// (the script reading of that launcher, actionfacts.HostScriptTwin).
var windowsFixtureViaCmd = map[string]bool{
	"windows-accessibility-utilman-replacement": true,
}

// windowsFixtureNotNativeInPowerShell lists the fixtures that carry a JSON
// literal with double quotes in a native program argument. Windows PowerShell
// 5.1 and PowerShell 7 pass such an argument to the program differently, so the
// analysis does not prove the literal that reaches the program
// (windowsNativeArgvUncertain) and the strict-only, detection-only rule has no
// exact proof there; the rule fires on the same fixture in the POSIX tool.
var windowsFixtureNotNativeInPowerShell = map[string]bool{
	"literal-sensitive-json-upload": true,
}

// TestWindowsClaimedRulesFireOnTheirFixtureAsAPowerShellToolCall runs each
// claimed rule's own attack fixtures of the product suite as a PowerShell tool
// call and expects the finding the suite expects, in the packs it expects
// (strict-only fixtures in the strict pack).
func TestWindowsClaimedRulesFireOnTheirFixtureAsAPowerShellToolCall(t *testing.T) {
	cases := readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl")
	checked := map[string]bool{}
	for _, pack := range toolCallCorpusProfiles {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusPackDirConnector(t, "windows-native-fixture", filepath.Join(guardrailPoliciesRoot(t), pack))
			for _, test := range cases {
				if !test.IsAttack || test.Command == "" || len(test.OSOverrides) != 0 ||
					!slices.Contains(windowsNativeFixtureRules, test.RuleID) {
					continue
				}
				// The Windows rows of a rule, in a Windows grammar: PowerShell
				// or cmd.exe text, or text without a dialect that no POSIX
				// program owns.
				if test.Dialect == actionfacts.DialectPOSIX {
					continue
				}
				if test.ProfilePosture == toolCallCorpusStrictOnlyPosture && pack != "strict" {
					continue
				}
				route := test.ExpectRoute
				if profileRoute := test.ProfileRoutes[pack]; profileRoute != "" {
					route = profileRoute
				}
				if route == "none" {
					continue
				}
				if windowsFixtureNotNativeInPowerShell[test.ID] {
					checked[test.RuleID] = true
					continue
				}
				checked[test.RuleID] = true
				command := test.Command
				if windowsFixtureViaCmd[test.ID] {
					command = "cmd /c " + command
				}
				args, err := json.Marshal(map[string]string{"command": command})
				if err != nil {
					t.Fatal(err)
				}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: actionfacts.Input{
						Tool: "PowerShell", Args: args, CWD: `C:\work`, ActiveHome: `C:\Users\alice`,
					},
					LegacyText: string(args), Connector: "windows-native-fixture", EnforcementCapable: true,
				})
				if !slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == test.RuleID }) {
					t.Errorf("%s/%s: no %s finding as a PowerShell tool call: %v", pack, test.ID, test.RuleID, FindingStrings(findings))
				}
			}
		})
	}
	for _, rule := range windowsNativeFixtureRules {
		if !checked[rule] {
			t.Errorf("no attack fixture of %s was run", rule)
		}
	}
}
