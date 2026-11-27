// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

// TestWindowsLauncherSpellingsPastTheBoundAreNeverACleanAllow
// (rel-1-0-10:GAP-0740, GAP-0741): a powershell launcher past the word limit
// (padded 3000 and 6000) or past the command size is truncated, in every
// tier, in each spelling of the shell around it: the quoted launcher path with
// a blank, a wrapper and its options, a leading redirection, xargs, start,
// wsl, a split quote, a line break, a local shell -c script, and the argv and
// JSON-array commands (the Codex shell tool). An ANSI-C quote before the
// launcher makes the tokenizer read the call as invalid syntax, which the
// syntax-error reading judges (s7/syntax-tail), not this screen. The
// launcher word in the data of another command (an ssh remote command) is not
// one: it is allowed with no alert, with at most the detection-only data-word
// record (the lead ruling on GAP-0382 and GAP-0760). The fixture is the toolcall corpus attack by id.
func TestWindowsLauncherSpellingsPastTheBoundAreNeverACleanAllow(t *testing.T) {
	type tier struct {
		name, pack      string
		strict, managed bool
	}
	tiers := []tier{{"default", "default", false, false}, {"permissive", "permissive", false, false},
		{"strict", "strict", true, false}, {"managed", "default", false, true}, {"managed-strict", "strict", true, true}}
	command, _ := windowsFixtureCommand(t, "windows-disable-multiple-defender-registry-controls")
	type spelling struct {
		id    string
		input func(launcher string) actionfacts.Input
		clean bool // the benign twin: stays out of the screen
	}
	text := func(build func(string) string) func(string) actionfacts.Input {
		return func(launcher string) actionfacts.Input {
			args, _ := json.Marshal(map[string]string{"command": build(launcher)})
			return actionfacts.Input{Tool: "Bash", Args: args, CWD: `C:\Users\alice\work`, ActiveHome: `C:\Users\alice`}
		}
	}
	argvOf := func(prefix ...string) func(string) actionfacts.Input {
		return func(launcher string) actionfacts.Input {
			return actionfacts.Input{Tool: "Bash", Argv: append(append([]string{}, prefix...), launcher), CWD: `C:\Users\alice\work`, ActiveHome: `C:\Users\alice`}
		}
	}
	// The Codex shell tool carries its command as an array of words.
	arrayOf := func(prefix ...string) func(string) actionfacts.Input {
		return func(launcher string) actionfacts.Input {
			args, _ := json.Marshal(map[string]any{"command": append(append([]string{}, prefix...), launcher)})
			return actionfacts.Input{Tool: "shell", Args: args, CWD: `C:\Users\alice\work`, ActiveHome: `C:\Users\alice`}
		}
	}
	rest := func(launcher string) string { return strings.TrimPrefix(launcher, "powershell") }
	spellings := []spelling{
		{"space-path-dq", text(func(l string) string { return `"C:\Program Files\PowerShell\7\pwsh.exe"` + rest(l) }), false},
		{"space-path-sq", text(func(l string) string { return `'C:\Program Files\PowerShell\7\pwsh.exe'` + rest(l) }), false},
		{"space-path-unix", text(func(l string) string { return `"/mnt/c/Program Files/PowerShell/7/pwsh.exe"` + rest(l) }), false},
		{"env-flag", text(func(l string) string { return "env -i " + l }), false},
		{"sudo-flag", text(func(l string) string { return "sudo -u root " + l }), false},
		{"redirect-lead", text(func(l string) string { return ">/dev/null 2>&1 " + l }), false},
		{"xargs", text(func(l string) string { return "echo x | xargs " + l }), false},
		{"start-title", text(func(l string) string { return `start "" ` + l }), false},
		{"wsl", text(func(l string) string { return "wsl.exe " + l }), false},
		{"wsl-e", text(func(l string) string { return "wsl -e " + l }), false},
		{"split-quote", text(func(l string) string { return `pow""ershell` + rest(l) }), false},
		{"cr-lead", text(func(l string) string { return "echo a\r" + l }), false},
		// An ANSI-C quote with an escaped quote before the launcher: the POSIX
		// analysis reads the call as invalid syntax, so the syntax-error
		// reading must hand the statement past the word limit to the bound
		// check (rel-1-0-10:GAP-0740 residual lead-dollarsq).
		{"lead-dollarsq", text(func(l string) string { return `echo $'a\'b'; ` + l }), false},
		{"bash-c-quote", text(func(l string) string { return "bash -lc '" + l + "'" }), false},
		{"sudo-bash-c-quote", text(func(l string) string { return "sudo -E bash -c \"" + l + "\"" }), false},
		{"eval-quote", text(func(l string) string { return `eval "` + l + `"` }), false},
		{"argv-bash-lc", argvOf("bash", "-lc"), false},
		{"argv-sh-c", argvOf("sh", "-c"), false},
		{"arr-bash-lc", arrayOf("bash", "-lc"), false},
		{"arr-sh-c", arrayOf("sh", "-c"), false},
		{"arr-env-sh-c", arrayOf("env", "X=1", "sh", "-c"), false},
		{"ssh-dq", text(func(l string) string { return `ssh host "` + l + `"` }), true},
		{"ssh-flags-sq", text(func(l string) string { return `ssh -o BatchMode=yes host '` + l + `'` }), true},
		{"argv-bash-lc-ssh", func(l string) actionfacts.Input {
			return actionfacts.Input{Tool: "Bash", Argv: []string{"bash", "-lc", `ssh host "` + l + `"`}, CWD: `C:\Users\alice\work`, ActiveHome: `C:\Users\alice`}
		}, true},
	}
	run := func(tr tier, in actionfacts.Input) []RuleFinding {
		text := string(in.Args)
		if text == "" {
			text = strings.Join(in.Argv, " ")
		}
		return dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: in, LegacyText: text, Connector: "windows-bounds", EnforcementCapable: true,
			StrictPolicy: tr.strict, ManagedInstall: tr.managed,
		})
	}
	for _, tr := range tiers {
		installToolCallCorpusPackDirConnector(t, "windows-bounds", filepath.Join(guardrailPoliciesRoot(t), tr.pack))
		for _, pad := range []int{3000, 6000} {
			launcher := windowsEncodedLayers(command+"; Write-Output '"+strings.Repeat("a", pad)+"'", 1)
			for _, sp := range spellings {
				findings := run(tr, sp.input(launcher))
				if sp.clean {
					// Lead ruling (GAP-0382, GAP-0760): a launcher name inside the
					// quoted remote command of ssh is DATA. The call keeps the
					// winrecall verdict, an allow with no alert, and carries at most
					// the detection-only data-word record, which is no cap.
					capped := slices.ContainsFunc(findings, func(f RuleFinding) bool {
						return !f.boundRecord && canonicalTrustedRuleID(f.RuleID) == evaluationLimitRuleID
					})
					if capped || !windowsBoundsAllowed(findings) {
						t.Errorf("%s pad%d %s: the launcher word in another command's data is truncated: %v", tr.name, pad, sp.id, FindingStrings(findings))
					}
					continue
				}
				if windowsBoundsAllowed(findings) {
					t.Errorf("%s pad%d %s: a clean allow: %v", tr.name, pad, sp.id, FindingStrings(findings))
				}
			}
		}
		// A launcher inside a local bash -c quote past the command size.
		big := "bash -c 'echo " + strings.Repeat("a", 100000) + "; " + windowsEncodedLayers("Get-Date", 1) + "'"
		if findings := run(tr, text(func(string) string { return big })("")); windowsBoundsAllowed(findings) {
			t.Errorf("%s big-bash-bashc: a clean allow: %v", tr.name, FindingStrings(findings))
		}
		// A long benign call that names no launcher stays as the readers left
		// it: the launcher screen adds nothing. The call is past the input
		// bound, so the byte floor TRUNCATES it at cap=bytes, the unknown tier
		// of its pack (rel-1-0-10:GAP-0611, GAP-0748; an allow before the
		// floor): the only limit finding it may carry is that one, and the
		// pack maps it (the five-tier rows are TestGAP0611OverInputBoundFiveTiers
		// and TestGAP0748POSIXShellOverTheInputBoundIsTruncatedFiveTiers).
		benign := "echo " + strings.Repeat("a", 100000) + "; ls cmd"
		if findings := run(tr, text(func(string) string { return benign })("")); tr.pack == "default" && !tr.strict && !tr.managed {
			for _, finding := range FindingStrings(findings) {
				if strings.HasPrefix(finding, evaluationLimitRuleID) && !strings.Contains(finding, "cap=bytes") {
					t.Errorf("%s: a long ordinary statement carries a limit finding other than the byte floor: %v", tr.name, FindingStrings(findings))
				}
			}
		}
	}
}
