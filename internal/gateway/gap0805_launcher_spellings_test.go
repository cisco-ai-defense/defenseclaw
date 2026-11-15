// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A launcher gets the verdict of the bare launcher however the Codex shell
// tool spells it, as an argv array or as one string: at an install path with a
// blank (rel-1-0-10:GAP-0804), behind a wrapper the over-limit screen reads
// (start "", wsl, wsl -e, xargs, env -i, sudo -u, nohup, timeout;
// rel-1-0-10:GAP-0805). The attack unit is the authorized_keys redirect
// fixture (overLimitWindowsRedirect). In every tier the redirect blocks, an
// ordinary script is allowed, and argv and string agree.

type gap0805Wrapper struct {
	name string
	argv []string
	text string
}

var gap0805Wrappers = []gap0805Wrapper{
	{"bare", nil, ""},
	{"env -i", []string{"env", "-i"}, "env -i "},
	{"sudo -u root", []string{"sudo", "-u", "root"}, "sudo -u root "},
	{`start ""`, []string{"start", ""}, `start "" `},
	{"wsl.exe", []string{"wsl.exe"}, "wsl.exe "},
	{"wsl -e", []string{"wsl", "-e"}, "wsl -e "},
	{"nohup", []string{"nohup"}, "nohup "},
	{"timeout 5", []string{"timeout", "5"}, "timeout 5 "},
	{"xargs", []string{"xargs"}, "echo x | xargs "},
}

var gap0805Launchers = []gap0711Launcher{
	{"powershell.exe -Command", "powershell.exe", []string{"-Command"}, false},
	{"pwsh -c", "pwsh", []string{"-c"}, false},
	{"install path with a blank", `C:\Program Files\PowerShell\7\pwsh.exe`, []string{"-Command"}, false},
	{"cmd /c", "cmd", []string{"/c"}, true},
	{"cmd.exe /d /c", "cmd.exe", []string{"/d", "/c"}, true},
}

func gap0805Text(w gap0805Wrapper, l gap0711Launcher, body string) string {
	prog := l.prog
	if strings.Contains(prog, " ") {
		prog = `"` + prog + `"`
	}
	quoted := `'` + strings.ReplaceAll(body, `'`, `''`) + `'`
	if l.cmd {
		quoted = `"` + body + `"`
	}
	return w.text + strings.Join(append(append([]string{prog}, l.flags...), quoted), " ")
}

func gap0805Argv(w gap0805Wrapper, l gap0711Launcher, body string) []interface{} {
	var out []interface{}
	for _, word := range append(append(append(append([]string{}, w.argv...), l.prog), l.flags...), body) {
		out = append(out, word)
	}
	return out
}

func TestGAP0805LauncherSpellingsDefault(t *testing.T)    { gap0805LauncherSpellings(t, 0) }
func TestGAP0805LauncherSpellingsPermissive(t *testing.T) { gap0805LauncherSpellings(t, 1) }
func TestGAP0805LauncherSpellingsStrict(t *testing.T)     { gap0805LauncherSpellings(t, 2) }
func TestGAP0805LauncherSpellingsManaged(t *testing.T)    { gap0805LauncherSpellings(t, 3) }
func TestGAP0805LauncherSpellingsManagedStrict(t *testing.T) {
	gap0805LauncherSpellings(t, 4)
}

func gap0805LauncherSpellings(t *testing.T, tierIndex int) {
	gap0589WindowsHost(t)
	cwd := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		id, ps, cmd string
		want        string // block, allow, or floor (at least the unknown tier)
	}{
		{"redirect", overLimitWindowsRedirect, overLimitWindowsRedirect, "block"},
		{"benign-git", `git log --oneline -5`, `git log --oneline -5`, "allow"},
		{"benign-listing", `Get-ChildItem C:\Users\alice\project`, `dir C:\Users\alice\project`, "allow"},
	}
	for _, tier := range boundedTestTiers[tierIndex : tierIndex+1] {
		floor := bounded.Unknown(tier.tier)
		api := gap0589TierAPI(t, "codex", tier.posture, tier.managed, tier.tier)
		decide := func(command interface{}) string {
			return api.evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			}).Action
		}
		for _, w := range gap0805Wrappers {
			for _, l := range gap0805Launchers {
				for _, r := range rows {
					body := r.ps
					if l.cmd {
						body = r.cmd
					}
					argv, text := decide(gap0805Argv(w, l, body)), decide(gap0805Text(w, l, body))
					for form, got := range map[string]string{"argv": argv, "string": text} {
						action := boundedParse(got)
						switch r.want {
						case "block":
							if action != bounded.Block {
								t.Errorf("%s/%s/%s/%s %s: action %s, want block", tier.name, w.name, l.name, r.id, form, got)
							}
						case "allow":
							if action != bounded.Allow {
								t.Errorf("%s/%s/%s/%s %s: action %s, want allow", tier.name, w.name, l.name, r.id, form, got)
							}
						case "floor":
							if action < floor {
								t.Errorf("%s/%s/%s/%s %s: action %s, want at least %s", tier.name, w.name, l.name, r.id, form, got, floor)
							}
						}
					}
					if argv != text {
						t.Errorf("%s/%s/%s/%s: argv %s differs from the same command as a string, %s", tier.name, w.name, l.name, r.id, argv, text)
					}
				}
			}
		}
	}
}
