// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// gap0700Heredoc is a JavaScript file written by a here-document: lists of
// names in braces, one per require line. The shell never brace-expands a
// here-document body, but a reader that expands the body as one word did,
// and the lists multiply: these fifteen make about 2*10^7 fields.
func gap0700Heredoc(alternatives []int) string {
	var body strings.Builder
	for line, count := range alternatives {
		names := make([]string, count)
		for i := range names {
			names[i] = "name" + strconv.Itoa(i)
		}
		body.WriteString("const { " + strings.Join(names, ",\n  ") + " } = require(\x27module" + strconv.Itoa(line) + "\x27)\n")
	}
	return body.String()
}

// gap0700Functions is a JavaScript file of functions that take a destructured
// parameter in braces and log a template string, written by a here-document.
// The shell never brace-expands the body; each brace list of four names would
// multiply a reader that expands the body as one word, fifteen of them to
// about 10^9 fields.
func gap0700Functions(count int) string {
	var body strings.Builder
	for i := 0; i < count; i++ {
		body.WriteString("function f" + strconv.Itoa(i) + "({a, b, c, d}) {\n  log(`x ${y}`)\n}\n")
	}
	return body.String()
}

// gap0700TierAPI is an action-mode API server with the connector installed at
// the policy tier, the shape the hook client evidence is judged under.
func gap0700TierAPI(t *testing.T, connector, tier string) *APIServer {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connector, tier)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.BlockAt = "HIGH"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tier)
	return &APIServer{scannerCfg: cfg}
}

// GAP-0700 and GAP-0721: one ordinary command must not keep the evaluator
// busy for minutes (a here-document body with many brace lists) or panic it
// (an assignment-only statement after a directory change). Each is answered
// in the hook window by both connectors, per user and managed, in the default
// and the strict tier, with the answer an ordinary command gets: allow.
func TestGAP0700GAP0721OrdinaryCommandsAreDecidedWithoutHangOrPanic(t *testing.T) {
	big := gap0700Heredoc([]int{7, 6, 4, 2, 4, 2, 2, 4, 2, 4, 2, 4, 2, 4, 2})
	small := gap0700Heredoc([]int{3, 2, 3})
	functions := gap0700Functions(15)
	fewFunctions := gap0700Functions(2)
	home := filepath.Join(t.TempDir(), "homes", "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	rows := []struct{ name, command, want string }{
		{"hang: heredoc with fifteen brace lists", "cat > /tmp/index.js << \x27EOF\x27\n" + big + "EOF\ncp /tmp/index.js ~/project/index.js", guardrailActionAllow},
		{"twin: heredoc with three brace lists", "cat > /tmp/index.js << \x27EOF\x27\n" + small + "EOF\ncp /tmp/index.js ~/project/index.js", guardrailActionAllow},
		{"protected twin: the same heredoc written to an SSH key file", "cat > ~/.ssh/authorized_keys << \x27EOF\x27\n" + big + "EOF", guardrailActionBlock},
		{"hang: heredoc of fifteen functions with destructured parameters", "cat > /tmp/index.js << \x27EOF\x27\n" + functions + "EOF\ncp /tmp/index.js ~/project/index.js", guardrailActionAllow},
		{"twin: heredoc of two functions with destructured parameters", "cat > /tmp/index.js << \x27EOF\x27\n" + fewFunctions + "EOF\ncp /tmp/index.js ~/project/index.js", guardrailActionAllow},
		{"protected twin: the same functions written to an SSH key file", "cat > ~/.ssh/authorized_keys << \x27EOF\x27\n" + functions + "EOF", guardrailActionBlock},
		{"panic: pid assignment in a background subshell", `cd /app && (exec 3<>/tmp/x.sock; cat <&3 & p=$!; printf "a" >&3; sleep 5; kill $p 2>/dev/null) > /tmp/out.txt 2>&1 & echo started; sleep 8; cat /tmp/out.txt`, guardrailActionAllow},
		{"twin: assignment-only statement after cd", `cd /app && x=1; echo "$x"`, guardrailActionAllow},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, tier := range []string{config.HookPolicyTierDefault, config.HookPolicyTierStrict} {
			api := gap0700TierAPI(t, connector, tier)
			for _, managed := range []bool{false, true} {
				cell := connector + "/" + tier + map[bool]string{false: "/per-user", true: "/managed"}[managed]
				for _, row := range rows {
					tool := "Bash"
					if connector == "codex" {
						tool = "exec_command"
					}
					type outcome struct {
						action string
						panic  any
					}
					done := make(chan outcome, 1)
					start := time.Now()
					go func() {
						var out outcome
						defer func() {
							out.panic = recover()
							done <- out
						}()
						out.action = gap0568ToolHookAction(t, api, connector, tool, home, cwd, row.command, true, managed)
					}()
					select {
					case out := <-done:
						if out.panic != nil {
							t.Errorf("%s %s: evaluator panic: %v", cell, row.name, out.panic)
						} else if out.action != row.want {
							t.Errorf("%s %s: action=%s, want %s", cell, row.name, out.action, row.want)
						}
						if took := time.Since(start); took > 3*time.Second {
							t.Errorf("%s %s: decided in %s", cell, row.name, took)
						}
					case <-time.After(10 * time.Second):
						t.Fatalf("%s %s: still evaluating after %s", cell, row.name, time.Since(start))
					}
				}
			}
		}
	}
}
