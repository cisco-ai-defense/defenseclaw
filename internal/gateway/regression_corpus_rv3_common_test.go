// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func rv3Join(n int, form, sep string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = strings.ReplaceAll(form, "%d", fmt.Sprint(i))
	}
	return strings.Join(parts, sep)
}

type rv3Env struct{ homes, home, cwd, state, keys string }

func rv3Setup(t *testing.T) rv3Env {
	t.Helper()
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	for _, d := range []string{cwd, filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	if err := os.WriteFile(state, []byte("guardrail:\n  mode: observe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	return rv3Env{homes, home, cwd, state, keys}
}

func rv3ClientCtx(t *testing.T, e rv3Env, tool, command string) context.Context {
	t.Helper()
	body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "rv3", "cwd": e.cwd,
		"tool_name": tool, "tool_input": map[string]any{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if targets, ok := hookpaths.Decode(hookpaths.Resolve(body)); ok {
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, targets)
	}
	return ctx
}

// rv3Hook answers one PreToolUse call through the connector hook.
func rv3Hook(t *testing.T, api *APIServer, e rv3Env, connector, tool, command string, client, managed bool) (string, time.Duration) {
	t.Helper()
	start := time.Now()
	ctx := context.Background()
	if client {
		ctx = rv3ClientCtx(t, e, tool, command)
	}
	if managed {
		ctx = withManagedHookPeer(ctx, managedHookPeer{Home: e.home})
		if err := os.Chmod(e.homes, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(e.homes, 0o700) }()
	}
	var action string
	if connector == "claudecode" {
		action = api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse", CWD: e.cwd, ToolName: tool,
			ToolInput: map[string]any{"command": command}}).Action
	} else {
		action = api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "PreToolUse", CWD: e.cwd, ToolName: "exec_command",
			ToolInput: map[string]any{"cmd": command}}).Action
	}
	return action, time.Since(start)
}

// rv3PS judges a PowerShell call on one of three routes: 0 the Claude Code
// PowerShell tool (hint), 1 a powershell tool (Codex re-reading), 2 Bash with
// a PowerShell hint.
func rv3PS(t *testing.T, e rv3Env, connector string, route int, command string, client, managed bool) (string, []string, actionfacts.Facts) {
	t.Helper()
	args, _ := json.Marshal(map[string]string{"command": command})
	input := actionfacts.Input{Args: args, CWD: e.cwd, ActiveHome: e.home}
	switch route {
	case 0:
		input.Tool, input.DialectHint = "PowerShell", actionfacts.DialectPowerShell
	case 1:
		input.Tool = "powershell"
	case 2:
		input.Tool, input.DialectHint = "Bash", actionfacts.DialectPowerShell
	}
	facts := actionfacts.Analyze(input)
	ctx := context.Background()
	if client {
		tool := "PowerShell"
		if route == 2 {
			tool = "Bash"
		}
		ctx = rv3ClientCtx(t, e, tool, command)
	}
	request := trustedActionRequest{Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true}
	if managed {
		ctx = withManagedHookPeer(ctx, managedHookPeer{Home: e.home})
		request.ProtectedHomeHook = true
		if err := os.Chmod(e.homes, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(e.homes, 0o700) }()
	}
	findings := dispatchTrustedAction(ctx, request)
	return buildVerdict(findings, "tool_call").Action, findingIDs(findings), facts
}

func rv3PSBenignForms() []struct{ name, command string } {
	block := strings.Join([]string{
		`$p = Join-Path $PWD "f%d.txt"`,
		`if (Test-Path $p) { Write-Output "yes $($p)" } else { Write-Output no }`,
		`foreach ($i in 1..3) { Write-Output $i }`,
		`$h%d = @{ Name = "n%d"; Size = 1 }`,
		`$o%d = & git rev-parse HEAD 2>&1`,
	}, "\n")
	return []struct{ name, command string }{
		{"array trailing commas 300", "$list = @(\n" + rv3Join(300, "  'item%d',", "\n") + "\n  'last'\n)\nWrite-Output $list"},
		{"param block 200", "param(\n" + rv3Join(200, "  [string]$p%d,", "\n") + "\n  [int]$last\n)\nWrite-Output $last"},
		{"param block attrs 100", "param(\n" + rv3Join(100, "  [Parameter(Mandatory=$false)]\n  [string]$p%d = 'x',", "\n") + "\n  [int]$last = 1\n)\nWrite-Output $last"},
		{"hashtable multiline 300", "$h = @{\n" + rv3Join(300, "  k%d = 1", "\n") + "\n}\nWrite-Output $h"},
		{"nested hashtables 100", "$cfg = @{\n" + rv3Join(100, "  s%d = @{ a = 1; b = 'x' }", "\n") + "\n}\n$cfg | ConvertTo-Json"},
		{"array of hashtables 150", "$rows = @(\n" + rv3Join(150, "  @{ Name = 'n%d'; Value = 1 },", "\n") + "\n  @{ Name = 'z'; Value = 0 }\n)\n$rows | Format-Table"},
		{"comma continuation 200", "$a = 1,\n" + rv3Join(200, "%d,", "\n") + "\n2\nWrite-Output $a"},
		{"call operator lines 100", rv3Join(100, "& git status --short", "\n")},
		{"assigned call operator 70", rv3Join(70, "$o%d = & git rev-parse HEAD", "\n")},
		{"assigned quoted call 70", rv3Join(70, `$o%d = & 'C:\Program Files\Git\bin\git.exe' status`, "\n")},
		{"assigned call 2>&1 60", rv3Join(60, "$r%d = & $env:ComSpec /c ver 2>&1", "\n")},
		{"redirect 2>&1 120", rv3Join(120, "Write-Output %d 2>&1", "\n")},
		{"redirect *>&1 120", rv3Join(120, "Write-Output %d *>&1", "\n")},
		{"Write-Host 120 LF", rv3Join(120, "Write-Host 'step %d'", "\n")},
		{"Write-Host 120 CRLF", rv3Join(120, "Write-Host 'step %d'", "\r\n")},
		{"Write-Host 128 semicolons", rv3Join(128, "Write-Host %d", "; ")},
		{"url with & in quotes 100", rv3Join(100, "$r%d = Invoke-WebRequest 'https://example.invalid/?a=1&b=2' -UseBasicParsing", "\n")},
		{"ordinary script 20 blocks", rv3Join(20, block, "\n")},
		{"if/else chain 60", rv3Join(60, "if ($x -eq %d) { $y = & git log -1 } elseif ($x) { $y = 2 } else { $y = 3 }", "\n")},
		{"try/catch 40", rv3Join(40, "try { $v%d = & git describe 2>&1 } catch { Write-Warning $_ }", "\n")},
		{"here-string then 100", "$s = @'\n" + rv3Join(500, "line %d; a | b & c", "\n") + "\n'@\n" + rv3Join(100, "Write-Output %d", "\n")},
	}
}

func rv3PosixBenignForms() []struct{ name, command string } {
	return []struct{ name, command string }{
		{"ls", "ls -la"},
		{"100 assignments", rv3Join(100, "a%d=1", "; ")},
		{"128 assignments", rv3Join(128, "a%d=1", "; ")},
		{"120 echo 2>&1", rv3Join(120, "echo %d 2>&1", "; ")},
		{"120 lines append", rv3Join(120, "echo line%d >> out.txt", "\n")},
		{"background 60", rv3Join(60, "sleep 0 &", " ") + " wait"},
		{"&& chain 100", rv3Join(100, "git status --short", " && ")},
		{"if script 60", "set -e\n" + rv3Join(60, "if [ -f f%d ]; then cat f%d; fi", "\n")},
		{"heredoc then 50", "cat > notes.md <<'EOF'\n" + rv3Join(500, "line %d & x; y", "\n") + "\nEOF\n" + rv3Join(50, "echo %d", "\n")},
		{"for loop 100", "for i in 1 2 3; do\n" + rv3Join(100, "echo %d", "\n") + "\ndone"},
		{"defenseclaw cli 60", rv3Join(60, "defenseclaw status", "; ")},
	}
}

// TestRV3BenignFourCells: benign calls in action mode, per-user and managed,
// Claude Code and Codex, with the client header.
func TestRV3BenignFourCells(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root")
	}
	e := rv3Setup(t)
	for _, connector := range []string{"claudecode", "codex"} {
		api := instructionProtectionTestAPI(t, connector, "action", "HIGH")
		for _, form := range rv3PosixBenignForms() {
			for _, managed := range []bool{false, true} {
				action, took := rv3Hook(t, api, e, connector, "Bash", form.command, true, managed)
				t.Logf("BENIGN-POSIX %-10s managed=%-5t %-22s action=%-5s %5dms", connector, managed, form.name, action, took.Milliseconds())
			}
		}
		for _, form := range rv3PSBenignForms() {
			for _, route := range []int{0, 1, 2} {
				for _, managed := range []bool{false, true} {
					action, ids, facts := rv3PS(t, e, connector, route, form.command, true, managed)
					t.Logf("BENIGN-PS %-10s route=%d managed=%-5t %-28s status=%-15s action=%-5s ids=%v", connector, route, managed, form.name, facts.Parse.Status, action, ids)
				}
			}
		}
	}
}

// TestRV3StateRows: observe mode, state write spellings over and under the
// budget, three cells per connector (gateway only, per-user client, managed client).
func TestRV3StateRows(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root")
	}
	e := rv3Setup(t)
	pad := rv3Join(200, "a%d=1", "; ")
	pad3k := rv3Join(3000, "a%d=1", "; ")
	decoy := rv3Join(130, "echo claw%d", "; ")
	rows := []struct{ name, command string }{
		{"plain alone", "printf c >> " + e.state},
		{"plain after 200", pad + "; printf c >> " + e.state},
		{"glob after 200", pad + "; printf c >> ~/.defense?law/config.yaml"},
		{"glob after 3000", pad3k + "; printf c >> ~/.defense?law/config.yaml"},
		{"glob first then 200", "printf c >> ~/.defense?law/config.yaml; " + pad},
		{"quote-split after 200", pad + "; printf c >> ~/.defense''claw/config.yaml"},
		{"quote-split after 3000", pad3k + "; printf c >> ~/.defense''claw/config.yaml"},
		{"backslash after 200", pad + `; printf c >> ~/.defense\claw/config.yaml`},
		{"bracket glob after 200", pad + "; printf c >> ~/.defense[c]law/config.yaml"},
		{"star glob after 200", pad + "; printf c >> ~/.defensecl*/config.yaml"},
		{"cd then relative alone", "cd ~/.defenseclaw; printf c >> config.yaml"},
		{"pad then cd+relative", pad + "; cd ~/.defenseclaw; printf c >> config.yaml"},
		{"cd then pad then relative", "cd ~/.defenseclaw; " + pad + "; printf c >> config.yaml"},
		{"var then write alone", `f=~/.defenseclaw/config.yaml; printf c >> "$f"`},
		{"pad then var+write", pad + `; f=~/.defenseclaw/config.yaml; printf c >> "$f"`},
		{"link then write alone", "ln -s " + e.state + " s9; printf c >> s9"},
		{"pad then link+write", pad + "; ln -s " + e.state + " s8; printf c >> s8"},
		{"link then pad then write", "ln -s " + e.state + " s7; " + pad + "; printf c >> s7"},
		{"decoy 130 then plain", pad + "; " + decoy + "; printf c >> " + e.state},
		{"decoy 130 then tilde", pad + "; " + decoy + "; printf c >> ~/.defenseclaw/config.yaml"},
		{"decoy 130 then glob", pad + "; " + decoy + "; printf c >> ~/.defense?law/config.yaml"},
		{"state read after 200", pad + "; cat ~/.defenseclaw/config.yaml"},
		{"benign 200", pad},
		{"keys after 200", pad + "; echo k >> " + e.keys},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		api := instructionProtectionTestAPI(t, connector, "observe", "HIGH")
		for _, row := range rows {
			var cells []string
			for _, cell := range []struct{ client, managed bool }{{false, false}, {true, false}, {true, true}} {
				action, took := rv3Hook(t, api, e, connector, "Bash", row.command, cell.client, cell.managed)
				cells = append(cells, fmt.Sprintf("%s(%dms)", action, took.Milliseconds()))
			}
			t.Logf("STATE %-10s %-28s gw=%-14s client=%-14s managed=%-14s", connector, row.name, cells[0], cells[1], cells[2])
			for _, s := range []string{"s7", "s8", "s9"} {
				_ = os.Remove(filepath.Join(e.cwd, s))
			}
		}
	}
}

// TestRV3Latency: in-process client + gateway per call, action mode,
// per-user with header, median of 7 runs per form.
func TestRV3Latency(t *testing.T) {
	e := rv3Setup(t)
	forms := []struct{ name, command string }{
		{"ls", "ls -la"},
		{"100 assignments", rv3Join(100, "a%d=1", "; ")},
		{"128 assignments", rv3Join(128, "a%d=1", "; ")},
		{"100 echo", rv3Join(100, "echo %d", "; ")},
		{"120 lines append", rv3Join(120, "echo line%d >> out.txt", "\n")},
		{"127 writes distinct", rv3Join(127, "echo x > f%d.txt", "; ")},
		{"3000 assignments", rv3Join(3000, "a%d=1", "; ")},
		{"30000 assignments", rv3Join(30000, "a%d=1", "; ")},
		{"30000 + state write", rv3Join(30000, "a%d=1", "; ") + "; printf c >> ~/.defenseclaw/config.yaml"},
		{"30000 claw + state write", rv3Join(30000, "echo claw%d", "; ") + "; printf c >> ~/.defenseclaw/config.yaml"},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		api := instructionProtectionTestAPI(t, connector, "action", "HIGH")
		for _, form := range forms {
			var runs, clientRuns []time.Duration
			action := ""
			for i := 0; i < 7; i++ {
				start := time.Now()
				_ = rv3ClientCtx(t, e, "Bash", form.command)
				clientRuns = append(clientRuns, time.Since(start))
				var took time.Duration
				action, took = rv3Hook(t, api, e, connector, "Bash", form.command, true, false)
				runs = append(runs, took)
			}
			sort.Slice(runs, func(i, j int) bool { return runs[i] < runs[j] })
			sort.Slice(clientRuns, func(i, j int) bool { return clientRuns[i] < clientRuns[j] })
			t.Logf("LAT %-10s %-26s bytes=%7d action=%-5s client_med=%8.1fms total_med=%8.1fms total_max=%8.1fms", connector, form.name, len(form.command), action,
				float64(clientRuns[3].Microseconds())/1000, float64(runs[3].Microseconds())/1000, float64(runs[6].Microseconds())/1000)
		}
	}
	for _, form := range []struct{ name, command string }{
		{"PS 120 Write-Host", rv3Join(120, "Write-Host 'step %d'", "\n")},
		{"PS ordinary 20 blocks", rv3PSBenignForms()[17].command},
		{"PS 3000 statements", rv3Join(3000, "Write-Output %d", "; ")},
	} {
		var runs []time.Duration
		action := ""
		for i := 0; i < 7; i++ {
			start := time.Now()
			action, _, _ = rv3PS(t, e, "codex", 1, form.command, true, false)
			runs = append(runs, time.Since(start))
		}
		sort.Slice(runs, func(i, j int) bool { return runs[i] < runs[j] })
		t.Logf("LAT codex-ps   %-26s bytes=%7d action=%-5s total_med=%8.1fms total_max=%8.1fms", form.name, len(form.command), action,
			float64(runs[3].Microseconds())/1000, float64(runs[6].Microseconds())/1000)
	}
}
