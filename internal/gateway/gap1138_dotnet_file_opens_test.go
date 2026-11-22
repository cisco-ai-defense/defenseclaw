// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap1138Form is one PowerShell spelling of a file open (%s is the target).
// verdict is what the open of a protected file is: "write" (the write rule of
// the file), "read" (no protected-write rule) or "unknown" (a mode or path
// known only at run time: never allowed, the unknown tier of the pack or the
// write rule). netPath reports a %s that is a .NET argument, where ~ names no
// home.
type gap1138Form struct {
	id, text, verdict string
	netPath           bool
}

// gap1138Forms are the .NET file opens that can write (or only read) a file:
// File.Open and the FileStream constructors with a FileMode and FileAccess,
// the FileInfo instance opens, the StreamWriter of New-Object -ArgumentList
// and a StreamWriter over a stream variable.
var gap1138Forms = []gap1138Form{
	{"File.Open Append", "$s = [IO.File]::Open(%s, 'Append'); $s.Close()", "write", true},
	{"File.Open FileMode Create", "[System.IO.File]::Open(%s, [System.IO.FileMode]::Create).Close()", "write", true},
	{"File.Open OpenOrCreate Write", "$s = [IO.File]::Open(%s, 'OpenOrCreate', 'Write'); $s.Close()", "write", true},
	{"File.Open Open (read and write)", "$s = [IO.File]::Open(%s, 'Open'); $s.Close()", "write", true},
	{"File.Open numeric mode", "$s = [IO.File]::Open(%s, 6); $s.Close()", "write", true},
	{"File.Open Open Read", "$s = [IO.File]::Open(%s, 'Open', 'Read'); $s.Close()", "read", true},
	{"File.Open enum Open Read", "$s = [IO.File]::Open(%s, [IO.FileMode]::Open, [IO.FileAccess]::Read); $s.Close()", "read", true},
	{"File.OpenWrite", "[IO.File]::OpenWrite(%s).Close()", "write", true},
	{"File.OpenRead", "[IO.File]::OpenRead(%s).Close()", "read", true},
	{"FileStream new", "$s = [IO.FileStream]::new(%s, 'Append'); $s.Close()", "write", true},
	{"New-Object FileStream", "$s = New-Object IO.FileStream(%s, 'Create'); $s.Close()", "write", true},
	{"New-Object FileStream -ArgumentList", "$s = New-Object -TypeName System.IO.FileStream -ArgumentList %s, 'Append'; $s.Close()", "write", true},
	{"New-Object FileStream Open Read", "$s = New-Object -TypeName IO.FileStream -ArgumentList %s, 'Open', 'Read'; $s.Close()", "read", true},
	{"FileInfo new OpenWrite", "$f = [IO.FileInfo]::new(%s); $s = $f.OpenWrite(); $s.Close()", "write", true},
	{"FileInfo cast AppendText", "$w = ([IO.FileInfo]%s).AppendText(); $w.WriteLine('zz'); $w.Close()", "write", true},
	{"New-Object FileInfo Open Append", "$f = New-Object System.IO.FileInfo(%s); $s = $f.Open('Append'); $s.Close()", "write", true},
	{"New-Object FileInfo Open Read", "$f = New-Object System.IO.FileInfo(%s); $s = $f.Open('Open', 'Read'); $s.Close()", "read", true},
	{"Get-Item CreateText", "$w = (Get-Item %s).CreateText(); $w.Close()", "write", false},
	{"Get-Item OpenRead", "(Get-Item %s).OpenRead().Close()", "read", false},
	{"New-Object StreamWriter -ArgumentList", "$w = New-Object -TypeName IO.StreamWriter -ArgumentList %s; $w.WriteLine('zz'); $w.Close()", "write", true},
	{"New-Object StreamWriter positional", "$w = New-Object System.IO.StreamWriter %s, $true; $w.WriteLine('zz'); $w.Close()", "write", true},
	{"StreamWriter over a stream variable", "$s = [IO.File]::Open(%s, $env:DCMODE); $w = [IO.StreamWriter]::new($s); $w.Write('zz'); $w.Close()", "write", true},
	{"File.Open mode at run time", "$s = [IO.File]::Open(%s, $env:DCMODE); $s.Close()", "unknown", true},
	{"File.Open path at run time", "[IO.File]::Open((Resolve-Path %s).Path, 'Append').Close()", "unknown", true},
}

// gap1138Target is one file the forms open; rules nil is the control, a
// project file no protected-write rule covers.
type gap1138Target struct {
	name, rel string
	rules     []string
}

func gap1138Targets() []gap1138Target {
	hookRules := []string{agentHookConfigWriteRuleID, agentHookConfigDisableRuleID}
	return []gap1138Target{
		{"codex config", filepath.Join(".codex", "config.toml"), hookRules},
		{"claude settings", filepath.Join(".claude", "settings.json"), hookRules},
		{"DefenseClaw state", filepath.Join(".defenseclaw", "config.yaml"), []string{"tamper.detector_state_write"}},
		{"project file", filepath.Join("proj", "out.txt"), nil},
	}
}

// gap1138Home makes the home and project the forms are judged in and points
// the agent homes at it.
func gap1138Home(t *testing.T) (home, project string) {
	t.Helper()
	home = filepath.Join(t.TempDir(), "home")
	project = filepath.Join(home, "proj")
	for name, body := range map[string]string{
		filepath.Join(home, ".codex", "config.toml"):       gap0048CodexConfig,
		filepath.Join(home, ".claude", "settings.json"):    "{}\n",
		filepath.Join(home, ".defenseclaw", "config.yaml"): "fixture: 1\n",
		filepath.Join(project, "notes.txt"):                "x\n",
		filepath.Join(project, "out.txt"):                  "x\n",
	} {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
		t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	}
	for _, key := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "OPENCODE_CONFIG_DIR", "XDG_CONFIG_HOME"} {
		t.Setenv(key, "")
	}
	return home, project
}

// gap1138Judge sends command as conn's shell tool call, from cwd, through
// the hook route, after the hook client resolved its paths. peer judges it
// behind a managed standalone gateway; restrict also takes the home away
// from that gateway while it judges (Linux and macOS).
func gap1138Judge(t *testing.T, handler http.HandlerFunc, conn, command, home, cwd string, peer, restrict bool) string {
	t.Helper()
	event, route := "PreToolUse", "/api/v1/"+conn+"/hook"
	var payload []byte
	switch conn {
	case "devin":
		payload = mustJSON(t, map[string]any{"hook_event_name": event, "session_id": "g1138", "prompt_id": "p1", "cwd": cwd,
			"tool_name": "exec", "tool_input": map[string]any{"command": command, "workdir": cwd}})
	case "antigravity":
		payload = mustJSON(t, map[string]any{"conversationId": "g1138", "stepIdx": 1, "workspacePaths": []string{cwd},
			"toolCall": map[string]any{"name": "run_command",
				"args": map[string]any{"Cwd": cwd, "CommandLine": command, "WaitMsBeforeAsync": 5000}}})
	case "codex":
		payload = mustJSON(t, map[string]any{"session_id": "g1138-cx", "hook_event_name": event, "cwd": cwd,
			"tool_name": "Bash", "tool_use_id": "t1", "turn_id": "u1", "tool_input": map[string]any{"command": command}})
	default:
		// Claude Code: its PowerShell tool on Windows, Bash elsewhere.
		route = "/api/v1/hook"
		tool := "Bash"
		if runtime.GOOS == "windows" {
			tool = "PowerShell"
		}
		payload = mustJSON(t, map[string]any{"session_id": "g1138-cc", "hook_event_name": event, "cwd": cwd,
			"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu_g1138", "tool_input": map[string]any{"command": command}})
	}
	req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	switch conn {
	case "antigravity":
		req.Header.Set("X-DefenseClaw-Antigravity-Event", event)
	case "codex":
		setTestCodexHookBinding(req, event, defaultTestCodexHookContract)
	}
	// The hook client runs as the user, before the gateway judges.
	if header := hookpaths.ResolveConnector(conn, "", event, payload); header != "" {
		req.Header.Set(hookpaths.Header, header)
	}
	if peer {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{UID: 1000, GID: 1000, PID: 1, Name: "g1138", Home: home}))
		if restrict && runtime.GOOS != "windows" && os.Geteuid() != 0 {
			if err := os.Chmod(home, 0); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(home, 0o700)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Body.String()
}

// gap1138Check reports what is wrong with got, the answer to form opening
// target in pack ("" when it is right).
func gap1138Check(got string, form gap1138Form, target gap1138Target, pack string) string {
	hookRules := []string{agentHookConfigWriteRuleID, agentHookConfigDisableRuleID, "tamper.detector_state_write"}
	hit := func(rules []string) bool {
		for _, rule := range rules {
			if strings.Contains(got, rule) {
				return true
			}
		}
		return false
	}
	action := hookConfigAction(got)
	switch {
	case target.rules != nil && form.verdict == "write":
		if !hit(target.rules) || action == "allow" {
			return fmt.Sprintf("%s, want one of %v and not allow, as for the redirect", action, target.rules)
		}
	case target.rules != nil && form.verdict == "unknown":
		if action == "allow" || !hit(append([]string{evaluationLimitRuleID}, target.rules...)) {
			return fmt.Sprintf("%s, want the unknown tier (%s) or %v, never allow", action, evaluationLimitRuleID, target.rules)
		}
	default:
		if hit(hookRules) {
			return fmt.Sprintf("%s: a read or an unprotected open raised a protected-write rule", action)
		}
		// The strict tier keeps its own reading of what it cannot prove.
		if target.rules == nil && pack != "strict" && action != "allow" {
			return fmt.Sprintf("%s: an open of an unprotected file is not allowed", action)
		}
	}
	return ""
}

// GAP-1138 on Linux and macOS: the .NET opens of gap1138Forms in the script
// of a pwsh -Command launcher (actionfacts.PowerShellLauncherScripts, read by
// the shared PowerShell write reader since GAP-1134) are judged as the
// redirect is, per-user and behind a managed gateway that cannot open the
// home, on every connector; a read-only open and every open of a project
// file stay allowed, and a mode or path known only at run time is never
// allowed.
func TestGAP1138PwshLauncherDotNetOpens(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Linux and macOS pwsh launcher reading; Windows: TestGAP1138DotNetFileOpens*")
	}
	home, project := gap1138Home(t)
	checked := 0
	for _, pack := range []string{"default", "strict"} {
		for _, conn := range []string{"claudecode", "codex", "devin", "antigravity"} {
			if pack == "strict" && conn != "codex" {
				continue
			}
			t.Run(pack+"/"+conn, func(t *testing.T) {
				installToolCallCorpusProfileConnector(t, conn, pack)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = conn
				store, logger := testStoreAndLogger(t)
				handler := (&APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}).handleAgentHook(conn)
				spellings := []string{"absolute"}
				if pack == "default" && conn == "claudecode" {
					spellings = append(spellings, "$HOME")
				}
				for _, target := range gap1138Targets() {
					for _, spelling := range spellings {
						word := `"` + filepath.Join(home, target.rel) + `"`
						if spelling == "$HOME" {
							word = `"$HOME/` + filepath.ToSlash(target.rel) + `"`
						}
						for _, form := range gap1138Forms {
							// The script is single-quoted for the POSIX shell; its
							// own strings are double-quoted.
							script := strings.ReplaceAll(fmt.Sprintf(form.text, word), "'", `"`)
							command := "pwsh -NoProfile -Command '" + script + "'"
							for _, peer := range []bool{false, true} {
								got := gap1138Judge(t, handler, conn, command, home, project, peer, true)
								checked++
								if problem := gap1138Check(got, form, target, pack); problem != "" {
									t.Errorf("peer=%v %s %s %s: %s\n%.600s", peer, target.name, spelling, form.id, problem, got)
								}
							}
						}
					}
				}
			})
		}
	}
	t.Logf("cells checked: %d", checked)
}
