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

// ADDITIVE ONLY (S7 lead constraint). psparse still has open review findings in
// the shapes it models, so its reading of a launcher may only ADD findings.
// For every call and every pack, the findings with the script reading must
// contain every finding the call as written raises, each at least as enforceable
// as it was; a launcher psparse cannot resolve must change nothing at all; and
// a launcher it resolves must add what its script raises.
func TestHostScriptTwinOnlyAddsFindings(t *testing.T) {
	type call struct {
		name, tool, command string
		opaque              bool // psparse cannot resolve the script: no reading
		strengthens         bool // the script reading makes a finding enforceable that the call as written only recorded or did not raise
	}
	calls := []call{
		{name: "wrapped authorized_keys append", tool: "PowerShell", command: `powershell -Command "Add-Content -Path C:\Users\alice\.ssh\authorized_keys -Value k"`},
		{name: "wrapped drive root removal", tool: "PowerShell", command: `pwsh -c 'ri -fo C:\ -rec'`, strengthens: true},
		{name: "call block removal", tool: "PowerShell", command: `& { Remove-Item C:\ -Recurse -Force }`},
		{name: "launcher with profile switch", tool: "PowerShell", command: `powershell -NoProfile -Command "Remove-Item C:\ -Recurse -Force"`},
		{name: "Git Bash launcher", tool: "Bash", command: `powershell.exe -c "Remove-Item C:\ -Recurse -Force"`, strengthens: true},
		{name: "cmd launcher", tool: "PowerShell", command: `cmd /c rmdir /q /s C:\`},
		{name: "cmd launcher in a POSIX tool keeps its backslashes", tool: "Bash", command: `cmd /c rmdir /q /s C:\`},
		{name: "cmd launcher with a quoted line in a POSIX tool", tool: "Bash", command: `cmd /c "rmdir /q /s C:\"`},
		{name: "benign wrapped read", tool: "PowerShell", command: `powershell -c "Get-Content README.md"`},
		{name: "benign bare", tool: "PowerShell", command: `Get-ChildItem C:\work`},
		{name: "benign posix", tool: "Bash", command: `ls -la /tmp`},
		{name: "attack posix", tool: "Bash", command: `rm -rf /`},
		{name: "variable payload", tool: "PowerShell", command: `powershell -Command $payload`, opaque: true},
		{name: "file launcher", tool: "PowerShell", command: `powershell -File C:\tmp\run.ps1`, opaque: true},
		{name: "stop parsing tail", tool: "PowerShell", command: `powershell -Command --% Remove-Item C:\ -Recurse -Force`, opaque: true},
		{name: "working directory", tool: "PowerShell", command: `pwsh -wd C:\work -c "Remove-Item C:\ -Recurse -Force"`, opaque: true},
		{name: "arbitrary path launcher", tool: "PowerShell", command: `C:\tmp\pwsh.exe -c "Remove-Item C:\ -Recurse -Force"`, opaque: true},
	}
	run := func(c call, enabled bool, pack string) []RuleFinding {
		args, err := json.Marshal(map[string]string{"command": c.command})
		if err != nil {
			t.Fatal(err)
		}
		input := actionfacts.Input{Tool: c.tool, Args: args, CWD: `C:\work`, ActiveHome: `C:\Users\alice`}
		return dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: string(args), Connector: "host-script-twin", EnforcementCapable: true,
			hostScriptTwinOff: !enabled,
		})
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusPackDirConnector(t, "host-script-twin", filepath.Join(guardrailPoliciesRoot(t), pack))
			added := map[string]bool{}
			for _, c := range calls {
				off := run(c, false, pack)
				on := run(c, true, pack)
				for _, base := range off {
					index := slices.IndexFunc(on, func(f RuleFinding) bool {
						return trustedActionFindingKey(f.RuleID) == trustedActionFindingKey(base.RuleID)
					})
					if index < 0 {
						t.Errorf("%s: the script reading removed %s", c.name, base.RuleID)
						continue
					}
					if base.contributesToEnforcement() && !on[index].contributesToEnforcement() {
						t.Errorf("%s: the script reading weakened %s from enforceable", c.name, base.RuleID)
					}
				}
				if c.opaque && (len(on) != len(off) || !slices.EqualFunc(on, off, func(a, b RuleFinding) bool {
					return a.RuleID == b.RuleID && a.contributesToEnforcement() == b.contributesToEnforcement()
				})) {
					t.Errorf("%s: an unresolved launcher changed the findings: off=%v on=%v", c.name, FindingStrings(off), FindingStrings(on))
				}
				for _, f := range on {
					if !slices.ContainsFunc(off, func(g RuleFinding) bool { return g.RuleID == f.RuleID }) {
						added[c.name+" "+f.RuleID] = true
					}
				}
				if c.strengthens && !slices.ContainsFunc(on, func(f RuleFinding) bool {
					return f.contributesToEnforcement() && !slices.ContainsFunc(off, func(g RuleFinding) bool {
						return g.RuleID == f.RuleID && g.contributesToEnforcement()
					})
				}) {
					t.Errorf("%s: the script reading added no enforceable finding: off=%v on=%v", c.name, FindingStrings(off), FindingStrings(on))
				}
			}
			if len(added) == 0 {
				t.Errorf("the script reading added no finding to any call")
			}
		})
	}
}

// rel-1-0-10:GAP-0157. A command that writes a file and then copies from the
// output of a command substitution to a fixed destination does not name a
// protected file, and is not an unresolved write to one; the same call written
// to a key file, or with a link made inside the substitution, still is.
func TestCopyFromACommandSubstitutionIsNotAKeyWrite(t *testing.T) {
	home := t.TempDir()
	run := func(t *testing.T, command string) []RuleFinding {
		t.Helper()
		installToolCallCorpusPackDirConnector(t, "gap0157", filepath.Join(guardrailPoliciesRoot(t), "default"))
		args, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		return dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:      actionfacts.Input{Tool: "Bash", Args: args, CWD: home, ActiveHome: home},
			LegacyText: string(args), Connector: "codex", EnforcementCapable: true,
		})
	}
	hasKeys := func(findings []RuleFinding) bool {
		return slices.ContainsFunc(findings, func(f RuleFinding) bool {
			return f.RuleID == "persistence.ssh_authorized_keys_command" && f.contributesToEnforcement()
		})
	}
	t.Run("ordinary destination", func(t *testing.T) {
		if findings := run(t, `echo hi > `+home+`/shot.raw && cp "$(cat `+home+`/shot.raw)" `+home+`/shot.png`); hasKeys(findings) {
			t.Fatalf("a copy to an ordinary file blocked as a key write: %v", FindingStrings(findings))
		}
	})
	t.Run("key file destination", func(t *testing.T) {
		if findings := run(t, `echo hi > `+home+`/shot.raw && cp "$(cat `+home+`/shot.raw)" `+home+`/.ssh/authorized_keys`); !hasKeys(findings) {
			t.Fatalf("a copy to the key file was not blocked: %v", FindingStrings(findings))
		}
	})
}
