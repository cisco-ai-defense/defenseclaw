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
						want := "alert"
						if p.managed || strings.Contains(p.name, "strict") {
							want = "block"
						}
						switch r.id {
						case "fixture-012":
							// A plain native call also has the unknown-operand partial
							// reading; a redirect proof does not erase that floor.
						case "ps-paren", "ps-at", "ps-amp-block", "ps-dot-block", "ps-redirect-then-echo-paren":
							// Whole-statement groupings are conservative readings. The
							// partial floor applies even when no mutation is proven.
							want = "alert"
							if p.managed || strings.Contains(p.name, "strict") {
								want = "block"
							}
						}
						wholeGrouping := r.id == "ps-paren" || r.id == "ps-sub" || r.id == "ps-at" || r.id == "ps-amp-block" || r.id == "ps-dot-block"
						if r.id != "fixture-012" && r.id != "ps-redirect-then-echo-paren" && !wholeGrouping {
							normalText := tarPart + "; echo hi > " + target
							if r.id == "ps-outfile-inputobject" {
								normalText = tarPart + "; Out-File -FilePath " + target + " -InputObject 0"
							}
							if r.id == "ps-here-outfile" {
								normalText = tarPart + "; 0 | Out-File " + target
							}
							normalArgs := map[string]any{"command": normalText}
							normal := shapeParityCall{name: "claudecode/PowerShell", conn: "claudecode", event: "PreToolUse",
								body: shapeParityEnvelope("PreToolUse", where.cwd, "PowerShell", normalArgs)}
							if call.conn == "antigravity" {
								normal = shapeParityNative("Bash", normalArgs, where.cwd)[0]
							}
							control := shapeParityHook(t, handlers[normal.conn], normal, p.managed)
							if shapeParityRank[control] > shapeParityRank[want] {
								want = control
							}
						}
						if shapeParityRank[got] < shapeParityRank[want] {
							t.Errorf("%s: got %s, want %s", call.name, got, want)
						}
					}
				})
			}
		}
	})
}

func TestGAP0988PowerShellPartialFloor(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		srv := gap0437Server(t, p, "claudecode", "action")
		installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
		command := windowsUnreadableStatement
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "PowerShell", Command: command})
		if facts.Parse.Status != actionfacts.StatusPartial {
			t.Fatal("fixture must be partial")
		}
		call := shapeParityCall{name: "claudecode/PowerShell", conn: "claudecode", event: "PreToolUse",
			body: shapeParityEnvelope("PreToolUse", t.TempDir(), "PowerShell", map[string]any{"command": command})}
		got := shapeParityHook(t, srv.handleAgentHook("claudecode"), call, p.managed)
		want := "alert"
		if p.managed || strings.Contains(p.name, "strict") {
			want = "block"
		}
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	})
}
