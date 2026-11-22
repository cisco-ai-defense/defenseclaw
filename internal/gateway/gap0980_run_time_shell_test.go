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
	"path/filepath"
	"strings"
	"testing"
)

// gap0980ActionRank orders hook verdicts from the weakest to the strictest.
var gap0980ActionRank = map[string]int{"allow": 0, "alert": 1, "block": 2}

// TestGAP0980RunTimeShellIsNeverWeakerThanTheLiteralShell: a shell named at
// run time ("$SHELL", "${SHELL:-sh}", $BASH, $0; bare or behind env, command,
// exec, nohup or time; with -c, -ec, -o pipefail -c, -c -- or a here-string)
// runs its TEXT as the literal shell does, so in every tier its verdict is at
// least that of the same call spelled with the literal bash
// (rel-1-0-10:GAP-0980). Each row is the literal call transformed in code.
func TestGAP0980RunTimeShellIsNeverWeakerThanTheLiteralShell(t *testing.T) {
	env := boundedLaneEnv(t)
	state := filepath.Join(env.home, ".defenseclaw")
	texts := []string{
		"rm -rf " + state,
		"printf x >> " + filepath.Join(state, "config.yaml"),
		"tee -a " + filepath.Join(env.home, ".ssh", "authorized_keys") + " < new.pub",
		"echo x >> " + filepath.Join(env.home, ".bashrc"),
	}
	// Each form has one %s for the shell word and one for the TEXT.
	forms := []string{
		"%s -c '%s'", "%s -ec '%s'", "%s -o pipefail -c '%s'", "%s -c -- '%s'",
		"env %s -c '%s'", "command %s -c '%s'", "exec %s -c '%s'", "nohup %s -c '%s'", "time %s -c '%s'",
		"%s <<< '%s'",
	}
	shells := []string{`"$SHELL"`, `"${SHELL:-sh}"`, `$BASH`, `$0`}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		decide := func(t *testing.T, command string) string {
			t.Helper()
			action, findings := boundedDecideClaudeCode(t, api, env, boundedLaneCall{tool: "Bash", input: map[string]any{"command": command}})
			if _, known := gap0980ActionRank[action]; !known {
				t.Fatalf("%q: action %q (findings %v) is no hook verdict", command, action, findings)
			}
			return action
		}
		for _, form := range forms {
			for textIndex, text := range texts {
				literal := strings.Replace(strings.Replace(form, "%s", "bash", 1), "%s", text, 1)
				t.Run(tier.name+"/"+form+"/"+string(rune('a'+textIndex)), func(t *testing.T) {
					floor := decide(t, literal)
					for _, shell := range shells {
						command := strings.Replace(strings.Replace(form, "%s", shell, 1), "%s", text, 1)
						if got := decide(t, command); gap0980ActionRank[got] < gap0980ActionRank[floor] {
							t.Errorf("%s: %q = %s, the literal shell call %s", tier.name, command, got, floor)
						}
					}
				})
			}
		}
	}
}

// TestGAP0981RunTimeProgramCountOptionIsNoShell: a program named at run time
// that is no shell takes -c as an option of its own ("$GREP" -c PATTERN
// FILE counts matches), so the call is read as the same call without the
// option, at the GAP-0018 tier of a run-time program, not as a shell that
// runs its operand (rel-1-0-10:GAP-0981).
func TestGAP0981RunTimeProgramCountOptionIsNoShell(t *testing.T) {
	env := boundedLaneEnv(t)
	keys := filepath.Join(env.home, ".ssh", "authorized_keys")
	rows := []struct{ counted, plain string }{
		{`"$GREP" -c ssh-rsa ` + keys, `"$GREP" -v ssh-rsa ` + keys},
		{`"$GREP" -ic ssh-rsa ` + keys, `"$GREP" -i ssh-rsa ` + keys},
		{`$WC -c ` + keys, `$WC -l ` + keys},
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for index, row := range rows {
			t.Run(tier.name+"/"+string(rune('a'+index)), func(t *testing.T) {
				counted, _ := boundedDecideClaudeCode(t, api, env, boundedLaneCall{tool: "Bash", input: map[string]any{"command": row.counted}})
				plain, _ := boundedDecideClaudeCode(t, api, env, boundedLaneCall{tool: "Bash", input: map[string]any{"command": row.plain}})
				if counted != plain {
					t.Errorf("%s: %q = %s, the same call without -c %s", tier.name, row.counted, counted, plain)
				}
			})
		}
	}
}
