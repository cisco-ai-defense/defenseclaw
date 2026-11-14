// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The Codex shell tool on a Windows host sends its command as an argv array.
// A launcher in it (powershell.exe -Command, pwsh -c, cmd /c) has its script
// read as the string command the same script is, in the dialect of the
// launcher, with or without the switch that turns startup scripts off
// (rel-1-0-10:GAP-0711), and a script over a reading bound is TRUNCATED at
// the shared floor (rel-1-0-10:GAP-0712). The attack unit is the existing
// authorized_keys redirect fixture (overLimitWindowsRedirect); no new command
// text is added. In every tier (default, permissive, strict, managed, managed
// strict):
//   - the redirect alone, in every launcher spelling, blocks as the bare
//     script does;
//   - a script over a reading bound is exactly what the same launcher as one
//     string is (the same findings' action), and at least the unknown tier of
//     the pack;
//   - an ordinary script is allowed, as the string is.

type gap0711Launcher struct {
	name  string
	prog  string
	flags []string
	cmd   bool
}

var gap0711Launchers = []gap0711Launcher{
	{"powershell.exe -Command", "powershell.exe", []string{"-Command"}, false},
	{"pwsh -Command", "pwsh", []string{"-Command"}, false},
	{"powershell -c", "powershell", []string{"-c"}, false},
	{"cmd /c", "cmd", []string{"/c"}, true},
	{"cmd /k", "cmd", []string{"/k"}, true},
	{"powershell.exe -NoProfile -Command", "powershell.exe", []string{"-NoProfile", "-Command"}, false},
	{"pwsh.exe -NoProfile -Command", "pwsh.exe", []string{"-NoProfile", "-Command"}, false},
	{"cmd.exe /d /c", "cmd.exe", []string{"/d", "/c"}, true},
	{"pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command", "pwsh",
		[]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"}, false},
}

func (l gap0711Launcher) argv(body string) []interface{} {
	out := []interface{}{l.prog}
	for _, flag := range l.flags {
		out = append(out, flag)
	}
	return append(out, body)
}

// text is the launcher and its script as one command string.
func (l gap0711Launcher) text(body string) string {
	quoted := `'` + strings.ReplaceAll(body, `'`, `''`) + `'`
	if l.cmd {
		quoted = `"` + body + `"`
	}
	return strings.Join(append(append([]string{l.prog}, l.flags...), quoted), " ")
}

func gap0711Pipelines(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("$o%d = & git log | Select-Object -First 1 | Out-String | Write-Output | Out-String | Write-Output | Out-String | Write-Output | Out-String | Out-Null", i)
	}
	return out
}

func gap0711CmdFiller(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("echo line%d", i)
	}
	return out
}

// One top-level test per tier, so the CI shards can split the -race cost.
func TestGAP0711CodexArgvLauncherBodiesDefault(t *testing.T)    { gap0711LauncherBodies(t, 0) }
func TestGAP0711CodexArgvLauncherBodiesPermissive(t *testing.T) { gap0711LauncherBodies(t, 1) }
func TestGAP0711CodexArgvLauncherBodiesStrict(t *testing.T)     { gap0711LauncherBodies(t, 2) }
func TestGAP0711CodexArgvLauncherBodiesManaged(t *testing.T)    { gap0711LauncherBodies(t, 3) }
func TestGAP0711CodexArgvLauncherBodiesManagedStrict(t *testing.T) {
	gap0711LauncherBodies(t, 4)
}

func gap0711LauncherBodies(t *testing.T, tierIndex int) {
	gap0589WindowsHost(t)
	cwd := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	redirect := overLimitWindowsRedirect
	type row struct {
		id string
		// ps and cmd are the script in each launcher's dialect.
		ps, cmd string
		// want is bounded.Block for a script the reading proves, else the
		// floor ("floor") or an allow ("allow").
		want string
		// limit is set for a script over a reading bound: the call carries
		// the evaluation-limit finding. A script of 100 statements is under
		// the CMD statement cap, so a proven block there has none.
		limit bool
	}
	rows := []row{
		{"redirect-alone", redirect, redirect, "block", false},
		{"redirect-after-100", gap0589Join(gap0589Filler(100), []string{redirect}),
			strings.Join(append(gap0711CmdFiller(100), redirect), " & "), "floor", false},
		{"redirect-after-200", gap0589Join(gap0589Filler(200), []string{redirect}),
			strings.Join(append(gap0711CmdFiller(200), redirect), " & "), "floor", true},
		// The remaining psfchk probe rows of GAP-0711/0712 (same fixtures,
		// layouts of the s7-psfchk matrix): the redirect first, after an
		// unreadable statement, in the middle, after ';' lists, after 120
		// ten-stage pipelines, behind a variable, and the atomic fixture.
		{"redirect-first-100", gap0589Join([]string{redirect}, gap0589Filler(100)),
			strings.Join(append([]string{redirect}, gap0711CmdFiller(100)...), " & "), "floor", false},
		{"redirect-unreadable-100-last", gap0589Join([]string{windowsUnreadableStatement}, gap0589Filler(100), []string{redirect}),
			strings.Join(append(gap0711CmdFiller(100), redirect), " & "), "floor", false},
		{"redirect-60-mid-60", gap0589Join(gap0589Filler(60), []string{redirect}, gap0589Filler(60)),
			strings.Join(append(append(gap0711CmdFiller(60), redirect), gap0711CmdFiller(60)...), " & "), "floor", false},
		{"redirect-semi-100-last", strings.Join(append(gap0589Filler(100), redirect), "; "),
			strings.Join(append(gap0711CmdFiller(100), redirect), " & "), "floor", false},
		{"redirect-pipelines-120-last", gap0589Join(gap0711Pipelines(120), []string{redirect}),
			strings.Join(append(gap0711CmdFiller(120), redirect), " & "), "floor", false},
		{"variable-5", "$k = 'C:\\Users\\alice\\.ssh\\authorized_keys'\n" + gap0589Join(gap0589Filler(5), []string{strings.Replace(redirect, `C:\Users\alice\.ssh\authorized_keys`, `$k`, 1)}),
			redirect, "same", false},
		{"variable-100", "$k = 'C:\\Users\\alice\\.ssh\\authorized_keys'\n" + gap0589Join(gap0589Filler(100), []string{strings.Replace(redirect, `C:\Users\alice\.ssh\authorized_keys`, `$k`, 1)}),
			redirect, "same", false},
		{"atomic-fixture", windowsAtomicParityPositives[3].command, windowsAtomicParityPositives[3].command, "same", false},
		{"ordinary-200", gap0589Join(gap0589Filler(200)), strings.Join(gap0711CmdFiller(200), " & "), "floor", true},
		{"ordinary-over-64KiB", "Get-ChildItem .\n# " + strings.Repeat("z", 64<<10), "echo hi & rem " + strings.Repeat("z", 64<<10), "floor", true},
		{"ordinary-listing", `Get-ChildItem C:\Users\alice\project`, `dir C:\Users\alice\project`, "allow", false},
		{"benign-git", `git log --oneline -5`, `git log --oneline -5`, "allow", false},
		{"benign-build", `npm test -- --watch=false`, `npm test -- --watch=false`, "allow", false},
		{"ordinary-30", gap0589Join(gap0589Filler(30)), strings.Join(gap0711CmdFiller(30), " & "), "allow", false},
	}
	for _, tier := range boundedTestTiers[tierIndex : tierIndex+1] {
		floor := bounded.Unknown(tier.tier)
		api := gap0589TierAPI(t, "codex", tier.posture, tier.managed, tier.tier)
		for _, l := range gap0711Launchers {
			for _, r := range rows {
				body := r.ps
				if l.cmd {
					body = r.cmd
				}
				decide := func(command interface{}) (string, []string) {
					resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
						ToolInput: map[string]interface{}{"command": command},
					})
					return resp.Action, resp.Findings
				}
				argvAction, argvFindings := decide(l.argv(body))
				textAction, textFindings := decide(l.text(body))
				t.Logf("ROW %s | %s | %s | argv %s | string %s", tier.name, l.name, r.id, argvAction, textAction)
				want := bounded.Allow
				switch r.want {
				case "block":
					want = bounded.Block
				case "floor":
					want = floor
				}
				got := boundedParse(argvAction)
				if r.want == "same" {
					// Only the parity with the string form below.
				} else if r.want == "floor" {
					// A proven block in the read part keeps its verdict.
					if got < want {
						t.Errorf("%s/%s/%s: argv action %s, want at least %s; findings %v", tier.name, l.name, r.id, argvAction, want, argvFindings)
					}
				} else if got != want {
					t.Errorf("%s/%s/%s: argv action %s, want %s; findings %v", tier.name, l.name, r.id, argvAction, want, argvFindings)
				}
				if r.limit && !boundedHasLimit(argvFindings, bounded.Items, false) {
					t.Errorf("%s/%s/%s: no %s finding on the argv call: %v", tier.name, l.name, r.id, evaluationLimitRuleID, argvFindings)
				}
				// The same launcher as one command string gets the same
				// verdict (rel-1-0-10:GAP-0735).
				if argvAction != textAction {
					t.Errorf("%s/%s/%s: argv action %s differs from the same command as a string, %s", tier.name, l.name, r.id, argvAction, textAction)
				}
				if r.limit && !boundedHasLimit(textFindings, bounded.Items, false) && !boundedHasLimit(textFindings, bounded.Bytes, false) {
					t.Errorf("%s/%s/%s: no %s finding on the string call: %v", tier.name, l.name, r.id, evaluationLimitRuleID, textFindings)
				}
			}
		}
	}
}

// A POSIX launcher in an argv command (the Codex shell tool on Linux and
// macOS: ["bash", "-lc", "<script>"]) with a script word past the 4 KiB
// word bound is read as the string script it is, in every tier: an ordinary
// script is allowed, and the state write the fixture holds after padding
// still blocks (rel-1-0-10:GAP-0712). A call with no readable body past the
// bounds (300 words of git add) is TRUNCATED at the shared floor.
func TestGAP0712CodexArgvPastBoundsFiveTiers(t *testing.T) {
	env := boundedLaneEnv(t)
	pad := strings.Repeat("# padding padding padding padding padding padding padding\n", 100)
	files := make([]interface{}, 0, 302)
	files = append(files, "git", "add")
	for i := 0; i < 300; i++ {
		files = append(files, fmt.Sprintf("file%d.txt", i))
	}
	for _, tier := range boundedTestTiers {
		floor := bounded.Unknown(tier.tier)
		api := gap0589TierAPI(t, "codex", tier.posture, tier.managed, tier.tier)
		decide := func(command interface{}) (string, []string) {
			resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: env.cwd,
				ToolInput: map[string]interface{}{"command": command},
			})
			return resp.Action, resp.Findings
		}
		for _, launcher := range [][]interface{}{{"bash", "-lc"}, {"sh", "-c"}} {
			ordinary, findings := decide(append(append([]interface{}{}, launcher...), pad+"echo ok"))
			t.Logf("ROW %s | %v | ordinary past 4 KiB | %s", tier.name, launcher, ordinary)
			if got := boundedParse(ordinary); got != bounded.Allow {
				t.Errorf("%s/%v ordinary script past the word bound: action %s, want allow; %v", tier.name, launcher, ordinary, findings)
			}
			seen, findings := decide(append(append([]interface{}{}, launcher...), pad+boundedShellSeen))
			t.Logf("ROW %s | %v | state write past 4 KiB | %s", tier.name, launcher, seen)
			if got := boundedParse(seen); got != bounded.Block {
				t.Errorf("%s/%v state write after padding: action %s, want block; %v", tier.name, launcher, seen, findings)
			}
		}
		action, findings := decide(files)
		t.Logf("ROW %s | git add x300 | %s", tier.name, action)
		if got := boundedParse(action); got < floor || !boundedHasLimit(findings, bounded.Items, true) {
			t.Errorf("%s/300 words: action %s, want at least %s with a TRUNCATED cap=items finding: %v", tier.name, action, floor, findings)
		}
		if action, findings := decide([]interface{}{"git", "status"}); boundedParse(action) != bounded.Allow {
			t.Errorf("%s/git status: action %s, want allow: %v", tier.name, action, findings)
		}
	}
}
