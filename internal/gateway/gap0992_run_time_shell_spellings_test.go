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
	"strings"
	"testing"
)

// gap0992Payloads are the TEXT a shell is asked to run: removal of the
// DefenseClaw state folder and a write to its config. Both block in every
// tier when the shell is literal.
var gap0992Payloads = []struct{ id, text string }{
	{"state removal", `rm -rf ~/.defenseclaw`},
	{"config write", `printf x >> ~/.defenseclaw/config.yaml`},
}

// gap0992Check asserts that a spelling blocks state removal and a config
// write in every tier, as the literal bash call does
// (rel-1-0-10:GAP-0992, GAP-0993, GAP-0994).
func gap0992Check(t *testing.T, form string) {
	t.Helper()
	env := boundedLaneEnv(t)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for _, payload := range gap0992Payloads {
			variant := strings.ReplaceAll(form, "%S", payload.text)
			t.Run(tier.name+"/"+payload.id, func(t *testing.T) {
				got, findings := boundedDecideClaudeCode(t, api, env, boundedLaneCall{tool: "Bash", input: map[string]any{"command": variant}})
				if _, known := gap0980ActionRank[got]; !known {
					t.Fatalf("%q: action %q is no hook verdict", variant, got)
				}
				if got != "block" {
					t.Errorf("%s: %q = %s (findings %v), want block", tier.name, variant, got, findings)
				}
			})
		}
	}
}

// TestGAP0992RunTimeShellSpellingsReadAsTheShellTheyName: every spelling that
// names the shell at run time (an empty quoted part next to the parameter,
// the :? operator, case modification, a directory pattern on ##, a static
// base name behind a run-time directory, /proc/self/exe, /proc/<pid>/exe,
// BASH_ARGV0, a lookup with -p, || or a pipe, readlink of SHELL) runs -c
// TEXT as literal bash does: state removal and a DefenseClaw config write
// block in all 5 tiers (rel-1-0-10:GAP-0992).
func TestGAP0992RunTimeShellSpellingsReadAsTheShellTheyName(t *testing.T) {
	programs := []struct{ id, word string }{
		{"errSHELL", `"${SHELL:?}"`}, {"errSHELLm", `"${SHELL:?unset}"`},
		{"emptysq", `"$SHELL"''`}, {"emptydq", `"$SHELL"""`}, {"leadsq", `''"$SHELL"`}, {"unqempty", `$SHELL""`},
		{"lower", `"${SHELL,,}"`}, {"pfx", `"${SHELL##/*/}"`},
		{"dirbash", `"${SHELL%/*}/bash"`}, {"prefbash", `"$PREFIX/bin/bash"`}, {"dnbash", `"$(dirname "$SHELL")/bash"`},
		{"procself", `/proc/self/exe`}, {"procpid", `/proc/$$/exe`}, {"argv0", `"$BASH_ARGV0"`},
		{"cmdpv", `$(command -pv bash)`}, {"whichor", `"$(command -v bash || echo sh)"`},
		{"whicha", `"$(which -a bash | head -n1)"`}, {"readl", `"$(readlink -f "$SHELL")"`},
	}
	for _, program := range programs {
		t.Run(program.id, func(t *testing.T) {
			gap0992Check(t, program.word+` -c '%S'`)
		})
	}
	t.Run("underscore", func(t *testing.T) {
		gap0992Check(t, `: bash; "$_" -c '%S'`)
	})
}

// TestGAP0993RunTimeShellIsReadWhereTheLiteralShellIsAChildCommand: eval
// STRING, find -exec, xargs and the $0 of a -c STRING whose name operand is a
// static shell name read a shell named at run time as the literal shell:
// block in all 5 tiers (rel-1-0-10:GAP-0993).
func TestGAP0993RunTimeShellIsReadWhereTheLiteralShellIsAChildCommand(t *testing.T) {
	forms := map[string]string{
		"eval-sq":       `eval '"$SHELL" -c "%S"'`,
		"eval-dq":       `eval "\"\$SHELL\" -c '%S'"`,
		"find-exec":     `find . -maxdepth 0 -exec "$SHELL" -c '%S' \;`,
		"xargs":         `echo x | xargs "$SHELL" -c '%S'`,
		"zero-name-sh":  `bash -c '"$0" -c "%S"' bash`,
		"literal-eval":  `eval 'bash -c "%S"'`,
		"literal-find":  `find . -maxdepth 0 -exec bash -c '%S' \;`,
		"literal-xargs": `echo x | xargs bash -c '%S'`,
	}
	for id, form := range forms {
		t.Run(id, func(t *testing.T) {
			gap0992Check(t, form)
		})
	}
}

// TestGAP0994ShellReadingItsScriptFromStdinJudgesTheScript: a static
// here-string or piped text given to bash (bash -s, a here-string, a pipe, the
// same through a nested bash) is read as the nested script, as the heredoc
// form is: state removal and a DefenseClaw config write block in all 5 tiers
// (rel-1-0-10:GAP-0994).
func TestGAP0994ShellReadingItsScriptFromStdinJudgesTheScript(t *testing.T) {
	forms := map[string]string{
		"stdin-s":      `echo '%S' | bash -s`,
		"herestr-s":    `bash -s <<< '%S'`,
		"pipe":         `echo '%S' | bash`,
		"herestr":      `bash <<< '%S'`,
		"pipe-in":      `echo 'bash -c "%S"' | bash`,
		"herestr-in":   `bash <<< 'bash -c "%S"'`,
		"herestr-var":  `"$SHELL" <<< '%S'`,
		"heredoc-ctrl": "bash <<'EOS'\n%S\nEOS",
	}
	for id, form := range forms {
		t.Run(id, func(t *testing.T) {
			gap0992Check(t, form)
		})
	}
}
