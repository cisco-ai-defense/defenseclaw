// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// hookCallBlocked reports whether a shell hook run denied the call, in any
// connector's native answer: an error status, or a deny/block document.
func hookCallBlocked(err error, out string) bool {
	if err != nil {
		return true
	}
	for _, marker := range []string{`"decision":"deny"`, `"decision":"block"`, `"action":"block"`,
		`"permission":"deny"`, `"permissionDecision":"deny"`, `"behavior":"deny"`, `"continue":false`} {
		if strings.Contains(out, marker) {
			return true
		}
	}
	return false
}

// hookFailureRecords reads every line of home/logs/hook-failures.jsonl.
func hookFailureRecords(t *testing.T, home string) []map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var record map[string]string
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("hook-failures.jsonl line %q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

// 1.0.4 review (GAP-0127): the gateway's fail-open recovery alert counts a
// hook-failures.jsonl line by its outcome. Every shell hook (not only Codex,
// Claude Code and Cursor) must therefore write the outcome it applied: a
// Hermes, Devin, Kiro, Antigravity or inspect-* call that strict
// availability blocked was logged "unknown" with fail mode open, and the
// gateway reported it as a call that ran unchecked. Copilot ignores strict
// availability (upstream fail-open), so its outcome follows the call.
func TestShellHookFailureRecordsNameTheOutcomeTheHookApplied(t *testing.T) {
	type hookRun struct {
		name   string
		conn   Connector
		invoke hookArgvCase
	}
	var runs []hookRun
	for _, conn := range []Connector{NewHermesConnector(), NewDevinConnector(), NewKiroConnector(), NewAntigravityConnector(),
		NewCopilotConnector(), NewClaudeCodeConnector(), NewCodexConnector(), NewCursorConnector()} {
		runs = append(runs, hookRun{conn.Name(), conn, hookArgvConnectorCase(t, conn.Name())})
	}
	for _, invoke := range hookArgvInspectCases() {
		if len(invoke.stdin) > 4096 {
			continue
		}
		runs = append(runs, hookRun{invoke.script, NewCodexConnector(), invoke})
	}
	for _, run := range runs {
		for _, mode := range []string{"open", "closed"} {
			for _, scenario := range []string{"outage", "strict-outage", "malformed", "oversized"} {
				t.Run(run.name+"/"+mode+"/"+scenario, func(t *testing.T) {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						_, _ = w.Write([]byte("not-json"))
					}))
					defer server.Close()
					addr := strings.TrimPrefix(server.URL, "http://")
					if strings.HasSuffix(scenario, "outage") {
						addr = "127.0.0.1:1"
					}
					home := t.TempDir()
					hookDir := filepath.Join(home, "hooks")
					opts := SetupOpts{DataDir: home, APIAddr: addr, APIToken: "scoped-test-token", HookFailMode: mode}
					if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, run.conn); err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, run.invoke.script)}, run.invoke.args...)...)
					cmd.Stdin = strings.NewReader(run.invoke.stdin)
					cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home)
					cmd.Env = append(cmd.Env, run.invoke.env...)
					switch scenario {
					case "strict-outage":
						cmd.Env = append(cmd.Env, "DEFENSECLAW_STRICT_AVAILABILITY=1")
					case "oversized":
						cmd.Env = append(cmd.Env, "DEFENSECLAW_HOOK_MAX_BODY=1")
					}
					output, err := cmd.CombinedOutput()
					blocked := hookCallBlocked(err, string(output))
					records := hookFailureRecords(t, home)
					if len(records) == 0 {
						if scenario != "malformed" {
							t.Fatalf("no hook-failures.jsonl record (blocked=%v):\n%s", blocked, output)
						}
						return
					}
					for _, record := range records {
						switch record["outcome"] {
						case "fail_open", "fail_closed", "diagnostic":
						default:
							t.Fatalf("record without the outcome the hook applied: %+v\n%s", record, output)
						}
					}
					want := "fail_open"
					if blocked {
						want = "fail_closed"
					}
					last := records[len(records)-1]
					if last["outcome"] != want {
						t.Fatalf("blocked=%v but the record says %q: %+v\n%s", blocked, last["outcome"], last, output)
					}
					if scenario == "strict-outage" && run.name != "copilot" && !blocked {
						t.Fatalf("strict availability did not block the outage:\n%s", output)
					}
				})
			}
		}
	}
}

// A record that is no delivery decision (a malformed traceparent the hook
// dropped before it asked the gateway) says diagnostic, so the gateway does
// not count the call, which the gateway checked, as unchecked.
func TestShellHookDiagnosticRecordsAreNotDeliveryOutcomes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"action":"allow","raw_action":"allow","hook_output":{}}`))
	}))
	defer server.Close()
	for _, conn := range []Connector{NewHermesConnector(), NewDevinConnector(), NewKiroConnector()} {
		t.Run(conn.Name(), func(t *testing.T) {
			invoke := hookArgvConnectorCase(t, conn.Name())
			home := t.TempDir()
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "scoped-test-token", HookFailMode: "open"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, invoke.script)}, invoke.args...)...)
			cmd.Stdin = strings.NewReader(invoke.stdin)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "TRACEPARENT=not-a-traceparent")
			output, err := cmd.CombinedOutput()
			if hookCallBlocked(err, string(output)) {
				t.Fatalf("an allowed call was blocked: %v\n%s", err, output)
			}
			records := hookFailureRecords(t, home)
			if len(records) != 1 || records[0]["outcome"] != "diagnostic" || !strings.Contains(records[0]["reason"], "traceparent") {
				t.Fatalf("records = %+v, want one diagnostic traceparent record\n%s", records, output)
			}
		})
	}
}

// Every hook-failures.jsonl writer in the shell templates names the outcome:
// a new branch that forgets it would bring back the unknown records the
// gateway counts by fail mode alone.
func TestEveryShellHookFailureRecordNamesItsOutcome(t *testing.T) {
	entries, err := hookFS.ReadDir("hooks")
	if err != nil {
		t.Fatal(err)
	}
	word := regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'[^']*'|[^\s"']+`)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sh") {
			continue
		}
		body, err := hookFS.ReadFile("hooks/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ReplaceAll(string(body), "\\\n", " ")
		for n, line := range strings.Split(text, "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "#") {
				continue
			}
			if strings.Contains(code, "defenseclaw_read_stdin_capped)") {
				t.Errorf("%s:%d: defenseclaw_read_stdin_capped without the outcome of its oversized branch: %s", entry.Name(), n+1, code)
			}
			at := strings.Index(code, "defenseclaw_log_hook_failure ")
			if at < 0 || strings.HasPrefix(code, "defenseclaw_log_hook_failure()") {
				continue
			}
			var args []string
			for _, w := range word.FindAllString(code[at+len("defenseclaw_log_hook_failure "):], -1) {
				if strings.HasPrefix(w, "2>") || strings.HasPrefix(w, ">") || w == "||" || w == ";" {
					break
				}
				args = append(args, w)
			}
			if len(args) < 6 {
				t.Errorf("%s:%d: defenseclaw_log_hook_failure without an outcome: %s", entry.Name(), n+1, code)
			}
		}
	}
}
