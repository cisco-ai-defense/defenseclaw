// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-10:GAP-1185 (review r1 rows R01-R15) at the Claude Code hook: a
// Write of a JavaScript file whose exec( is on a name the file binds again,
// shadows, or reaches past (a prototype write through bracketed keys) keeps
// CG-EXEC-001 in every tier, and a file that only reads a proven regular
// expression (as a log argument or in an object) is allowed in every tier.
func TestGAP1185RegExpProofAtTheHookEveryTier(t *testing.T) {
	lines := func(l ...string) string { return strings.Join(l, "\n") }
	for _, row := range []struct {
		id, content string
		fires       bool
	}{
		{"R01-catch-binding", `const re = /x/; try { throw cp } catch (re) { re.exec(cmd) }`, true},
		{"R02-default-param", `const re = /x/; function f(re = cp) { return re.exec(cmd) }`, true},
		{"R03-nested-destructure", `const re = /x/; function f({value: re}) { return re.exec(cmd) }`, true},
		{"R04-regexp-or-cp", `const re = new RegExp("x") || cp; re.exec(cmd)`, true},
		{"R05-regexp-param-shadow", `function f(RegExp) { const re = new RegExp("x"); return re.exec(cmd) }`, true},
		{"R06-eval-property-write", `const re = /x/; eval("re.exec = require('child_process').exec"); re.exec(cmd);`, true},
		{"R07-eval-prototype-write", `const re = /x/; eval("RegExp.prototype.exec = require('child_process').exec"); re.exec(cmd);`, true},
		{"R08-benign-leading-import", lines(`import fs from 'fs'`, `const re = /x/;`, `re.exec(cmd);`), false},
		{"R09-benign-leading-call", lines(`console.log('ok')`, `const re = /x/;`, `re.exec(cmd);`), false},
		{"R10-benign-literal", `const re = /x/; re.exec(cmd);`, false},
		{"R11-benign-constructor", `const re = new RegExp("x"); re.exec(cmd);`, false},
		{"R12-control-command", `const cp = require("child_process"); cp.exec(cmd);`, true},
		{"R13-bracket-prototype-write", lines(
			`const re = /x/;`,
			`re.constructor["prototype"]["exec"] = require("child_process").exec;`,
			`re.exec(cmd);`), true},
		{"R14-benign-object-shorthand", lines(`const re = /x/;`, `const obj = {re};`, `re.exec(cmd);`), false},
		{"R15-benign-log-argument", lines(`const re = /x/;`, `console.log(re);`, `re.exec(cmd);`), false},
	} {
		for _, tier := range []struct {
			name, pack string
			managed    bool
		}{
			{"default", "default", false},
			{"permissive", "permissive", false},
			{"strict", "strict", false},
			{"managed", "default", true},
			{"managed-strict", "strict", true},
		} {
			t.Run(row.id+"/"+tier.name, func(t *testing.T) {
				action, rules := postGAP1185Write(t, row.content, tier.pack, tier.managed)
				fired := slices.Contains(rules, codeGuardExecRule)
				if fired != row.fires {
					t.Fatalf("CG-EXEC-001 fired=%v, want %v (action %q, rules %v)", fired, row.fires, action, rules)
				}
				if row.fires && action == "allow" {
					t.Fatalf("action allow with CG-EXEC-001, want alert or block")
				}
				if !row.fires && action != "allow" {
					t.Fatalf("action %q on RegExp matching (rules %v), want allow", action, rules)
				}
			})
		}
	}
}

// codeGuardExecRule is the CodeGuard rule the GAP-1185 rows read.
const codeGuardExecRule = "CG-EXEC-001"

// postGAP1185Write posts one Claude Code PreToolUse Write of run.js with the
// content, as the per-user hook or as a managed hook peer, under the rule
// pack, and returns the action and the rule ids of the answer.
func postGAP1185Write(t *testing.T, content, pack string, managed bool) (string, []string) {
	t.Helper()
	cwd := t.TempDir()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePack = pack
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	body := mustJSON(t, map[string]any{"session_id": "s", "hook_event_name": "PreToolUse",
		"tool_name": "Write", "cwd": cwd,
		"tool_input": map[string]any{"file_path": filepath.Join(cwd, "run.js"), "content": content}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
	if managed {
		req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: t.TempDir()}))
	}
	rec := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(rec, req)
	var answer struct {
		Action  string   `json:"action"`
		RuleIDs []string `json:"rule_ids"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status=%d err=%v body=%s", rec.Code, err, rec.Body.String())
	}
	return answer.Action, answer.RuleIDs
}
