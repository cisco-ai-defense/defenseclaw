// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// coworkWorkspaceServer is the mcp_server object Cowork's engine sends with
// its workspace tools (measured on 2.1.309).
func coworkWorkspaceServer() map[string]interface{} {
	return map[string]interface{}{"name": "workspace", "source": "sdk"}
}

type coworkVerdict struct {
	action, raw, severity string
	wouldBlock            bool
	findings              []string
}

func coworkVerdictOf(resp claudeCodeHookResponse) coworkVerdict {
	findings := slices.Clone(resp.Findings)
	slices.Sort(findings)
	return coworkVerdict{resp.Action, resp.RawAction, resp.Severity, resp.WouldBlock, findings}
}

func (v coworkVerdict) equal(o coworkVerdict) bool {
	return v.action == o.action && v.raw == o.raw && v.severity == o.severity && v.wouldBlock == o.wouldBlock &&
		slices.Equal(v.findings, o.findings)
}

// The regression corpus of shell commands, replayed as Cowork's VM shell
// (mcp__workspace__bash with the engine's workspace server), gets exactly
// the verdict Claude Code's Bash gets for the same command, under every
// shipped profile, in action and observe mode, on PreToolUse and
// PermissionRequest. So a benign command that Bash allows is never blocked
// in Cowork, and an attack Bash blocks is blocked in Cowork too.
//
// On a Windows gateway Claude Code's Bash keeps every dialect reading of a
// command (PowerShell, cmd and POSIX) unless Git Bash alone reads it, while
// the Cowork shell, which runs in a Linux VM, is always read as POSIX. There
// the verdicts must be equal for every command the Windows hint reads as
// POSIX, and for the others the Cowork verdict must never be the stricter
// one (no benign command blocked only in Cowork).
//
// Every corpus row is judged in the strict profile and in one of the other
// two, not in all twelve profile, mode and event cells (see the rotation
// below).
func TestCoworkShellReplaysTheToolCallCorpusWithBashVerdicts(t *testing.T) {
	cases := readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl")
	var commands []toolCallCorpusCase
	for _, test := range cases {
		tool := strings.ToLower(strings.TrimSpace(test.Tool))
		if test.Command == "" || (tool != "" && tool != "shell" && tool != "bash") ||
			(test.Dialect != "" && test.Dialect != actionfacts.DialectPOSIX) {
			continue
		}
		commands = append(commands, test)
	}
	if len(commands) < 400 {
		t.Fatalf("corpus gave %d POSIX shell rows; the replay needs the full corpus", len(commands))
	}
	root := guardrailPoliciesRoot(t)
	var compared, bashBlocks, benign, windowsOnly int
	// The owner's test budget: no cross product of corpus row x profile x
	// mode x event. Each row is judged in two cells, not all twelve: once in
	// the strict profile and once in the default or the permissive one, with
	// mode and event turning between the two and from row to row. Attack and
	// benign rows rotate separately, so each walks all the cells in turn; the
	// check at the end shows every cell judged both.
	type cell struct{ profile, mode, event string }
	apis := map[cell]*APIServer{}
	api := func(c cell) *APIServer {
		if apis[c] == nil {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = c.mode
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePackDir = filepath.Join(root, c.profile)
			apis[c] = &APIServer{scannerCfg: cfg}
		}
		return apis[c]
	}
	modes, events := []string{"action", "observe"}, []string{"PreToolUse", "PermissionRequest"}
	type judgment struct {
		test         toolCallCorpusCase
		cell         cell
		cwd          string
		bash, cowork coworkVerdict
	}
	var judgments []judgment
	turn := map[bool]int{}
	for _, test := range commands {
		k := turn[test.IsAttack]
		turn[test.IsAttack]++
		cwd := test.CWD
		if cwd == "" {
			cwd = "/repo"
		}
		for _, c := range []cell{
			{"strict", modes[k%2], events[(k/2)%2]},
			{[]string{"default", "permissive"}[(k/4)%2], modes[(k+1)%2], events[(k/2+1)%2]},
		} {
			api(c)
			judgments = append(judgments, judgment{test: test, cell: c, cwd: cwd})
		}
	}
	// The verdicts are independent reads of one APIServer per cell, as a
	// gateway serves concurrent hooks, so they run on every CPU; the checks
	// below read the results in corpus order.
	forEachOnEveryCPU(len(judgments), func(i int) {
		j := &judgments[i]
		evaluate := func(tool string, server map[string]interface{}) coworkVerdict {
			payload := map[string]interface{}{"hook_event_name": j.cell.event, "tool_name": tool}
			if server != nil {
				payload["mcp_server"] = server
			}
			return coworkVerdictOf(apis[j.cell].evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: j.cell.event, ToolName: tool, CWD: j.cwd,
				ToolInput: map[string]interface{}{"command": j.test.Command},
				Payload:   payload,
			}))
		}
		j.bash = evaluate("Bash", nil)
		j.cowork = evaluate("mcp__workspace__bash", coworkWorkspaceServer())
	})
	judged := map[cell][2]int{}
	for _, j := range judgments {
		test, c, bash, cowork := j.test, j.cell, j.bash, j.cowork
		counts := judged[c]
		if test.IsAttack {
			counts[0]++
		} else {
			counts[1]++
		}
		judged[c] = counts
		compared++
		if bash.raw == "block" {
			bashBlocks++
		}
		if !test.IsAttack {
			benign++
		}
		if coworkBashReadsPOSIX(test.Command) {
			if !cowork.equal(bash) {
				t.Errorf("%s/%s %s %q (%s): Cowork %+v, Bash %+v", c.profile, c.mode, c.event, test.Command, test.ID, cowork, bash)
			}
		} else {
			windowsOnly++
			if coworkActionRank(cowork.raw) > coworkActionRank(bash.raw) {
				t.Errorf("%s/%s %s %q (%s): Cowork %+v is stricter than Bash %+v on Windows", c.profile, c.mode, c.event, test.Command, test.ID, cowork, bash)
			}
		}
	}
	for _, profile := range []string{"default", "strict", "permissive"} {
		for _, mode := range modes {
			for _, event := range events {
				if counts := judged[cell{profile, mode, event}]; counts[0] == 0 || counts[1] == 0 {
					t.Errorf("cell %s/%s %s judged %d attack and %d benign rows; the rotation must give it both", profile, mode, event, counts[0], counts[1])
				}
			}
		}
	}
	if bashBlocks == 0 {
		t.Fatal("no corpus command blocked as Bash: the replay proves nothing")
	}
	t.Logf("compared %d verdicts on %s (%d Bash blocks, %d benign rows, %d read by every Windows dialect)",
		compared, runtime.GOOS, bashBlocks, benign, windowsOnly)
}

// coworkBashReadsPOSIX reports whether Claude Code's Bash reads command as
// POSIX alone on this host: everywhere but Windows, and on Windows when Git
// Bash alone reads it (claudeCodeWindowsShellDialect).
func coworkBashReadsPOSIX(command string) bool {
	if runtime.GOOS != "windows" {
		return true
	}
	args, _ := json.Marshal(map[string]string{"command": command})
	return claudeCodeWindowsShellDialect(actionfacts.Input{
		Tool: "Bash", Args: args, ActiveHome: hookActiveHome(context.Background()),
	}) == actionfacts.DialectPOSIX
}

func coworkActionRank(action string) int {
	switch action {
	case "block":
		return 3
	case "confirm":
		return 2
	case "alert":
		return 1
	}
	return 0
}

// A workspace bash call without the engine's own server (an older engine, or
// a user MCP server of that name) is still inspected as a shell command.
func TestCoworkShellWithoutTheSDKServerIsStillInspectedAsAShell(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	for _, server := range []map[string]interface{}{nil, {"name": "workspace", "source": "user"}} {
		payload := map[string]interface{}{}
		if server != nil {
			payload["mcp_server"] = server
		}
		resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "mcp__workspace__bash",
			ToolInput: map[string]interface{}{"command": "rm -rf /"}, Payload: payload,
		})
		if resp.RawAction != "block" || resp.Action != "block" {
			t.Errorf("server %v: action=%q raw=%q, want block", server, resp.Action, resp.RawAction)
		}
	}
}

// Cowork's web fetch, and a browser navigation, get the verdict Claude
// Code's WebFetch gets for the URL.
func TestCoworkFetchAndNavigateGetWebFetchVerdicts(t *testing.T) {
	urls := []string{
		"https://example.com", "https://docs.python.org/3/library/json.html",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		"http://127.0.0.1:18970/api/v1/health", "file:///etc/passwd",
		"https://pastebin.com/raw/abc123", "http://[::1]:8080/",
	}
	for _, profile := range []string{"default", "strict"} {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "claudecode"
		cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
		api := &APIServer{scannerCfg: cfg}
		evaluate := func(tool string, input map[string]interface{}, server map[string]interface{}) coworkVerdict {
			payload := map[string]interface{}{}
			if server != nil {
				payload["mcp_server"] = server
			}
			return coworkVerdictOf(api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: tool, ToolInput: input, Payload: payload,
			}))
		}
		for _, url := range urls {
			webFetch := evaluate("WebFetch", map[string]interface{}{"url": url}, nil)
			fetch := evaluate("mcp__workspace__web_fetch", map[string]interface{}{"url": url}, coworkWorkspaceServer())
			if !fetch.equal(webFetch) {
				t.Errorf("%s web_fetch %q: %+v, WebFetch %+v", profile, url, fetch, webFetch)
			}
			navigate := evaluate("mcp__Claude_Browser__navigate", map[string]interface{}{"url": url, "tabId": 7},
				map[string]interface{}{"name": "Claude_Browser", "source": "sdk"})
			if navigate.raw != webFetch.raw || navigate.severity != webFetch.severity {
				t.Errorf("%s navigate %q: raw=%q severity=%q, WebFetch raw=%q severity=%q",
					profile, url, navigate.raw, navigate.severity, webFetch.raw, webFetch.severity)
			}
		}
	}
}

// forEachOnEveryCPU runs do(0) .. do(n-1) on GOMAXPROCS goroutines and
// returns when all are done. do must only write its own index's result and
// must not call t.Fatal (t.Error is safe).
func forEachOnEveryCPU(n int, do func(i int)) {
	var next atomic.Int64
	var wg sync.WaitGroup
	for range min(runtime.GOMAXPROCS(0), n) {
		wg.Go(func() {
			for i := int(next.Add(1) - 1); i < n; i = int(next.Add(1) - 1) {
				do(i)
			}
		})
	}
	wg.Wait()
}
