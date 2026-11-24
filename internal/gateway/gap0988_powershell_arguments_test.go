// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package gateway

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP0988PowerShellArgumentStatements(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	var f12 string
	for _, c := range shapeParityCases(t) {
		if c.id == "gap/p0-round_GAP-1536/012" {
			f12, _ = c.args["command"].(string)
		}
	}
	at := strings.LastIndex(f12, " > ")
	if at < 0 {
		t.Fatal("fixture 012 missing redirect")
	}
	tarPart, target := f12[:at], f12[at+3:]
	root := t.TempDir()
	home, outside := filepath.Join(root, "home"), filepath.Join(root, "work")
	inside := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), outside, inside} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	rows := []struct{ id, command string }{
		{"fixture-012", f12},
		{"after-extraction", tarPart + "; echo hi > " + target},
		{"sub-dq", `echo "$(` + tarPart + `)" > ` + target},
		{"sub-bare", "echo $(" + tarPart + ") > " + target},
		{"sub-append", "echo $(" + tarPart + ") >> " + target},
		{"ps-sub", "$(" + tarPart + ") > " + target},
		{"ps-paren", "(" + tarPart + ") > " + target},
		{"ps-echo-paren", "echo (" + tarPart + ") > " + target},
		{"ps-here-outfile", "@\"\n$(" + tarPart + ")\n\"@ | Out-File " + target},
		{"procsub", "cat <(" + tarPart + ") > " + target},
		{"ps-echo-at", "echo @(" + tarPart + ") > " + target},
		{"ps-at", "@(" + tarPart + ") > " + target},
		{"ps-amp-block", "& { " + tarPart + " } > " + target},
		{"ps-dot-block", ". { " + tarPart + " } > " + target},
		{"ps-echo-amp-block", "echo (& { " + tarPart + " }) > " + target},
		{"ps-wo-paren", "Write-Output (" + tarPart + ") > " + target},
		{"ps-echo-paren-append", "echo (" + tarPart + ") >> " + target},
		{"ps-echo-paren-all", "echo (" + tarPart + ") *> " + target},
		{"ps-echo-paren-2", "echo (" + tarPart + ") 2> " + target},
		{"ps-outfile-inputobject", "Out-File -FilePath " + target + " -InputObject (" + tarPart + ")"},
		{"ps-echo-paren-then", "echo (" + tarPart + "); echo hi > " + target},
		{"ps-redirect-then-echo-paren", "echo hi > " + target + "; echo (" + tarPart + ")"},
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		handlers := map[string]http.HandlerFunc{}
		for _, conn := range []string{"claudecode", "antigravity"} {
			srv := gap0437Server(t, p, conn, "action")
			installToolCallCorpusProfileConnector(t, conn, p.pack)
			handlers[conn] = srv.handleAgentHook(conn)
		}
		for _, where := range []struct{ name, cwd string }{{"outside", outside}, {"inside", inside}} {
			for _, r := range rows {
				t.Run(where.name+"/"+r.id, func(t *testing.T) {
					args := map[string]any{"command": r.command}
					cc := shapeParityCall{name: "claudecode/PowerShell", conn: "claudecode", event: "PreToolUse",
						body: shapeParityEnvelope("PreToolUse", where.cwd, "PowerShell", args)}
					calls := append([]shapeParityCall{cc}, shapeParityNative("Bash", args, where.cwd)...)
					for _, call := range calls {
						got := shapeParityHook(t, handlers[call.conn], call, p.managed)
						fmt.Printf("G88\t%s\t%s\t%s\t%s\t%s\n", p.name, where.name, r.id, call.name, got)
						// Each row is judged against the same commands spelled as
						// plain statements in the order PowerShell runs them: an
						// argument command (a paren, subexpression, array,
						// string or here-string expansion) runs before its
						// parent opens a redirect target, while an invoked block
						// runs after its own redirect opened (fixture 012,
						// GAP-0946). Where that spelling blocks, the row blocks.
						// No partial-reading floor raises a read call (GAP-1015).
						normalText := tarPart + "; echo hi > " + target
						switch r.id {
						case "fixture-012", "ps-amp-block", "ps-dot-block":
							normalText = f12
						case "ps-redirect-then-echo-paren":
							normalText = "echo hi > " + target + "; " + tarPart
						case "ps-outfile-inputobject":
							normalText = tarPart + "; Out-File -FilePath " + target + " -InputObject 0"
						case "ps-here-outfile":
							normalText = tarPart + "; 0 | Out-File " + target
						}
						normalArgs := map[string]any{"command": normalText}
						normal := shapeParityCall{name: "claudecode/PowerShell", conn: "claudecode", event: "PreToolUse",
							body: shapeParityEnvelope("PreToolUse", where.cwd, "PowerShell", normalArgs)}
						if call.conn == "antigravity" {
							normal = shapeParityNative("Bash", normalArgs, where.cwd)[0]
						}
						control := shapeParityHook(t, handlers[normal.conn], normal, p.managed)
						fmt.Printf("G88C\t%s\t%s\t%s\t%s\t%s\n", p.name, where.name, r.id, call.name, control)
						if control == "block" && got != "block" {
							t.Errorf("%s: got %s, want block (the plain statements block)", call.name, got)
						}
					}
				})
			}
		}
	})
}

// TestGAP0988PowerShellUnreadFloor: a PowerShell call whose reading skipped
// text it never read (actionfacts.ParseResult.Unread: no balanced end, a --%
// remainder) gets the shared unknown tier, mapped by pack: an alert in
// default, permissive and the managed default pack, a block in strict and
// managed-strict (GAP-1016). An ordinary call that reads as partial only
// because a command's operand grammar, a value or a call target is not
// modeled was read, and keeps its verdict: allow (GAP-1015).
func TestGAP0988PowerShellUnreadFloor(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	unread := []struct{ id, command string }{
		{"unbalanced-subexpression", "Write-Output $(Get-Date"},
		// a --% remainder that is not a plain local argv (a %NAME% expansion);
		// a plain one is read as the argv (GAP-2087)
		{"stop-parsing", "ping.exe --% -n 1 %COMPUTERNAME%"},
	}
	ordinary := []struct{ id, command string }{
		{"listing", "Get-ChildItem -Path src -Recurse -Filter *.go | Select-Object -First 5"},
		{"git", "git log --oneline -5; git status --short"},
		{"search", "Get-Content README.md | Select-String -Pattern TODO"},
		{"subexpression", windowsUnreadableStatement},
		{"env-build", "$env:GOOS = 'windows'; go build ./..."},
		{"hashtable", "@{ Name = 'x'; Count = 3 } | ConvertTo-Json"},
		{"dotnet", "dotnet build -c Release"},
	}
	read := func(command string) actionfacts.ParseResult {
		return actionfacts.Analyze(actionfacts.Input{Tool: "PowerShell", Command: command,
			DialectHint: actionfacts.DialectPowerShell}).Parse
	}
	for _, row := range unread {
		if parse := read(row.command); parse.Status != actionfacts.StatusPartial || !parse.Unread {
			t.Fatalf("fixture %s must read partial with unread text: %+v", row.id, parse)
		}
	}
	for _, row := range ordinary {
		if parse := read(row.command); parse.Status != actionfacts.StatusPartial || parse.Unread {
			t.Fatalf("fixture %s must read partial with no unread text: %+v", row.id, parse)
		}
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		handlers := map[string]http.HandlerFunc{}
		for _, conn := range []string{"claudecode", "antigravity"} {
			srv := gap0437Server(t, p, conn, "action")
			installToolCallCorpusProfileConnector(t, conn, p.pack)
			handlers[conn] = srv.handleAgentHook(conn)
		}
		cwd := t.TempDir()
		judge := func(command string) []shapeParityCall {
			args := map[string]any{"command": command}
			cc := shapeParityCall{name: "claudecode/PowerShell", conn: "claudecode", event: "PreToolUse",
				body: shapeParityEnvelope("PreToolUse", cwd, "PowerShell", args)}
			return append([]shapeParityCall{cc}, shapeParityNative("Bash", args, cwd)...)
		}
		floor := "alert"
		if p.pack == "strict" {
			floor = "block"
		}
		for _, row := range unread {
			for _, call := range judge(row.command) {
				if got := shapeParityHook(t, handlers[call.conn], call, p.managed); got != floor {
					t.Errorf("unread %s %s: got %s, want %s (the unknown tier of the pack)", row.id, call.name, got, floor)
				}
			}
		}
		for _, row := range ordinary {
			for _, call := range judge(row.command) {
				if got := shapeParityHook(t, handlers[call.conn], call, p.managed); got != "allow" {
					t.Errorf("ordinary %s %s: got %s, want allow (read, only its grammar is not modeled)", row.id, call.name, got)
				}
			}
		}
	})
}
