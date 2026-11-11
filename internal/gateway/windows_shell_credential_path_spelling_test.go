// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// windowsShellVerdict is the path rules a shell word judges, with whether each
// one can enforce, for a command run by a user whose home is C:\Users\alice.
func windowsShellVerdict(t *testing.T, tool, command string) map[string]bool {
	t.Helper()
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: actionfacts.Input{
			Tool: tool, Command: command,
			CWD: `C:\Users\alice`, ActiveHome: `C:\Users\alice`,
		},
		LegacyText: command, Connector: "claudecode", EnforcementCapable: true,
	})
	verdict := make(map[string]bool, len(findings))
	for _, finding := range findings {
		if strings.HasPrefix(finding.RuleID, "PATH-") {
			verdict[finding.RuleID] = verdict[finding.RuleID] || finding.contributesToEnforcement()
		}
	}
	return verdict
}

func describeVerdict(verdict map[string]bool) string {
	ids := make([]string, 0, len(verdict))
	for id, enforcing := range verdict {
		ids = append(ids, fmt.Sprintf("%s(enforce=%v)", id, enforcing))
	}
	sort.Strings(ids)
	return "[" + strings.Join(ids, " ") + "]"
}

// plainPathVerdict leaves out the rules written for Windows spellings
// (PATH-WIN-*): the question is whether the file gets the verdict the rule of
// its name gives in the slash spelling.
func plainPathVerdict(verdict map[string]bool) string {
	plain := make(map[string]bool, len(verdict))
	for id, enforcing := range verdict {
		if !strings.HasPrefix(id, "PATH-WIN-") {
			plain[id] = enforcing
		}
	}
	return describeVerdict(plain)
}

// enforces reports a verdict with a path rule that can block.
func enforces(verdict map[string]bool) bool {
	for _, enforcing := range verdict {
		if enforcing {
			return true
		}
	}
	return false
}

// A shell word that names a credential file with a Windows backslash path
// (quoted, as a shell keeps the backslashes) gets the verdict the same file
// gets in the slash spelling: the home-prefixed path rules write the slash
// form, and the file is the same one.
func TestShellWriteOfCredentialFileNamedWithBackslashPathMatchesSlashSpelling(t *testing.T) {
	forms := []string{
		"echo x >> %s",
		"printf x >> %s",
		"echo x > %s",
		"echo x | tee -a %s",
		"cp x %s",
		"touch %s",
	}
	// windowsRule is true for a file one of the rules written by hand for the
	// Windows spelling names (PATH-WIN-*): it keeps that rule, so the same
	// outcome is compared, not the label.
	files := []struct {
		rel         string
		windowsRule bool
	}{
		{`.netrc`, false},
		{`.git-credentials`, true},
		{`.aws\credentials`, true},
		{`.kube\config`, true},
		{`.docker\config.json`, false},
		{`.npmrc`, false},
		{`.pypirc`, false},
	}
	roots := []string{`C:\Users\alice`, `c:\users\ALICE`, `C:\Users\bob`, `D:\Profiles\carol`}
	for _, tool := range []string{"Bash", "shell"} {
		for _, file := range files {
			slashRel := strings.ReplaceAll(file.rel, `\`, "/")
			for _, root := range roots {
				slashRoot := strings.ReplaceAll(root, `\`, "/")
				spellings := []string{
					root + `\` + file.rel,
					root + "/" + slashRel,
					slashRoot + `\` + file.rel,
					strings.ToUpper(root + `\` + file.rel),
				}
				for _, form := range forms {
					control := windowsShellVerdict(t, tool, fmt.Sprintf(form, `"`+slashRoot+"/"+slashRel+`"`))
					for _, spelling := range spellings {
						for _, quote := range []string{`'`, `"`} {
							command := fmt.Sprintf(form, quote+spelling+quote)
							got := windowsShellVerdict(t, tool, command)
							if file.windowsRule {
								if enforces(got) != enforces(control) {
									t.Errorf("%s %q: %s, slash spelling %s", tool, command,
										describeVerdict(got), describeVerdict(control))
								}
								continue
							}
							if plainPathVerdict(got) != plainPathVerdict(control) {
								t.Errorf("%s %q: plain rules %s, slash spelling %s", tool, command,
									plainPathVerdict(got), plainPathVerdict(control))
							}
						}
					}
				}
			}
		}
	}
}

// The slash spelling of the credential file is itself judged by a rule of its
// name in a home of the usual shape; this is the control the comparison above
// relies on, so a change to the rules cannot make both sides empty.
func TestShellWriteOfCredentialFileInSlashSpellingStillMatchesItsRule(t *testing.T) {
	for _, file := range []struct{ rel, rule, windowsRule string }{
		{".netrc", "PATH-NETRC", ""},
		{".git-credentials", "PATH-GIT-CREDS", "PATH-WIN-GIT-CREDS"},
		{".aws/credentials", "PATH-AWS-CREDS", "PATH-WIN-AWS-CREDS"},
		{".kube/config", "PATH-KUBE", "PATH-WIN-KUBE-CONFIG"},
		{".docker/config.json", "PATH-DOCKER", ""},
		{".npmrc", "PATH-NPMRC", ""},
		{".pypirc", "PATH-PYPIRC", ""},
	} {
		command := "echo x >> C:/Users/alice/" + file.rel
		got := windowsShellVerdict(t, "Bash", command)
		_, plain := got[file.rule]
		_, windows := got[file.windowsRule]
		if !plain && !windows {
			t.Errorf("%q: %s, want %s or %s", command, describeVerdict(got), file.rule, file.windowsRule)
		}
	}
}

// The credential files the typed rules protect are blocked in every shape the
// report names: the verdict enforces, in the default pack as the connector
// installs it.
func TestShellWriteOfNetrcNamedWithBackslashPathEnforces(t *testing.T) {
	for _, tool := range []string{"Bash", "shell", "exec_command"} {
		for _, command := range []string{
			`echo x >> 'C:\Users\alice\.netrc'`,
			`echo x >> "C:\Users\alice\.netrc"`,
			`echo x >> "C:\\Users\\alice\\.netrc"`,
			`printf x >> 'C:\Users\alice\.netrc'`,
			`echo x | tee -a 'C:\Users\alice\.netrc'`,
			`cp x 'C:\Users\alice\.netrc'`,
			`touch 'C:\Users\alice\.netrc'`,
			`echo x >> 'C:/Users/alice\.netrc'`,
			`echo x >> 'C:\Users\alice/.netrc'`,
		} {
			if got := windowsShellVerdict(t, tool, command); !got["PATH-NETRC"] {
				t.Errorf("%s %q: %s, want PATH-NETRC to enforce", tool, command, describeVerdict(got))
			}
		}
	}
}

// An ordinary file with a Windows backslash path, and a file whose name only
// resembles a credential file, stays allowed: no path rule at all.
func TestShellWriteOfOrdinaryFileNamedWithBackslashPathStaysAllowed(t *testing.T) {
	for _, tool := range []string{"Bash", "shell"} {
		for _, name := range []string{
			`C:\Users\alice\notes.txt`,
			`C:\Users\alice\proj\netrc.md`,
			`C:\Users\alice\proj\.npmrc-notes.md`,
			`C:\Users\alice\.config\app\settings.json`,
			`C:\Users\alice\Documents\credentials.txt`,
			`C:\src\proj\config`,
			`D:\work\proj\.kube-notes`,
		} {
			for _, form := range []string{"echo x >> %s", "echo x | tee -a %s", "cp x %s", "touch %s"} {
				command := fmt.Sprintf(form, `'`+name+`'`)
				if got := windowsShellVerdict(t, tool, command); len(got) != 0 {
					t.Errorf("%s %q: %s, want no path rule", tool, command, describeVerdict(got))
				}
			}
		}
	}
}
