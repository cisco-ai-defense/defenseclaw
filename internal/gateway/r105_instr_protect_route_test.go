// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// r105CodexRoute posts Codex hook events the way the installed per-user hook
// script does: to /api/v1/codex/hook on loopback with the connector-scoped
// hook token, through the gateway's token middleware, with no client
// evidence header (the per-user hook sends none).
type r105CodexRoute struct {
	t     *testing.T
	api   *APIServer
	token string
}

func newR105CodexRoute(t *testing.T, home, blockAt string) *r105CodexRoute {
	t.Helper()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	token, err := connector.EnsureHookAPIToken(dataDir, "codex")
	if err != nil || token == "" {
		t.Fatalf("mint the codex hook token: %v", err)
	}
	api := instructionProtectionTestAPI(t, "codex", "action", blockAt)
	api.scannerCfg.DataDir = dataDir
	api.scannerCfg.Gateway.Token = "master-token"
	return &r105CodexRoute{t: t, api: api, token: token}
}

func (r *r105CodexRoute) post(body map[string]interface{}) (string, []string) {
	r.t.Helper()
	raw := mustJSON(r.t, body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("X-DefenseClaw-Hook-Event", body["hook_event_name"].(string))
	req.Header.Set("X-DefenseClaw-Hook-Contract", r.api.hookProfileForConnector("codex").ContractID)
	rec := httptest.NewRecorder()
	r.api.tokenAuth(r.api.handleUnifiedConnectorHook("codex")).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		r.t.Fatalf("%v: status %d: %s", body["hook_event_name"], rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		r.t.Fatal(err)
	}
	action, _ := out["action"].(string)
	var findings []string
	if list, ok := out["findings"].([]interface{}); ok {
		for _, item := range list {
			if text, ok := item.(string); ok {
				findings = append(findings, text)
			}
		}
	}
	return action, findings
}

func (r *r105CodexRoute) start(session, cwd string) {
	r.t.Helper()
	r.post(map[string]interface{}{"hook_event_name": "SessionStart", "session_id": session, "cwd": cwd, "source": "startup", "model": "x"})
}

func (r *r105CodexRoute) bash(session, cwd, command string) (string, []string) {
	r.t.Helper()
	return r.post(map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": session, "cwd": cwd, "tool_name": "Bash",
		"tool_use_id": "t1", "turn_id": "u1", "tool_input": map[string]interface{}{"command": command},
	})
}

// GAP-1503 (decided: not a defect of the startup snapshot). The installed
// per-user Codex hook route authenticates with the connector-scoped hook
// token, so the gateway records the session's startup snapshot. A write to
// the AGENTS.md the session started with is then identity-proved: it blocks
// in action wherever HIGH blocks (guardrail.block_at HIGH, as the lab's
// managed hosts set, or the strict pack). The balanced pack's own block level
// is CRITICAL, so with no block_at the same proved HIGH finding is an alert
// (BALANCED-DEFAULTS rule 1/2: an organization raises it with block_at). The
// AGENTS.md the session itself creates stays its own in every case.
func TestR105GAP1503PerUserCodexRouteRecordsTheStartupSnapshot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	for _, tc := range []struct {
		blockAt string
		want    string
	}{
		{"HIGH", guardrailActionBlock},
		{"", "alert"},
	} {
		t.Run("block_at "+tc.blockAt, func(t *testing.T) {
			home := testenv.PrivateTempDir(t)
			restore, err := connector.BindUserHomeDir(home)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(restore)
			route := newR105CodexRoute(t, home, tc.blockAt)
			existing := filepath.Join(home, "existing")
			writeActiveAgentTestFile(t, existing, "AGENTS.md")
			route.start("pre-existing", existing)
			for _, command := range []string{"printf x >> AGENTS.md", "printf x >> " + filepath.Join(existing, "AGENTS.md")} {
				if action, findings := route.bash("pre-existing", existing, command); action != tc.want || !findingStringHasRuleID(findings, "COG-AGENTS-MD") {
					t.Fatalf("%s: action=%q findings=%v, want %s COG-AGENTS-MD", command, action, findings, tc.want)
				}
			}
			created := filepath.Join(home, "created")
			if err := os.MkdirAll(created, 0o700); err != nil {
				t.Fatal(err)
			}
			route.start("created", created)
			writeActiveAgentTestFile(t, created, "AGENTS.md")
			for i := 0; i < 2; i++ {
				if action, findings := route.bash("created", created, "printf x >> AGENTS.md"); action == guardrailActionBlock || findingStringHasRuleID(findings, "COG-AGENTS-MD") {
					t.Fatalf("edit %d of the session's own AGENTS.md: action=%q findings=%v", i+1, action, findings)
				}
			}
		})
	}
}

// GAP-1004 (decided: fixed at base by the loaded-file identity of GAP-1064).
// A hard link to a nested CLAUDE.md, outside every searched directory and
// made before the session's InstructionsLoaded event, is the loaded file
// under another name: writing it blocks, from the gateway's own view and
// from the hook client's evidence. Removing the link name stays allowed.
func TestR105GAP1004UnindexedHardLinkOfANestedLoadedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hard links in a shell form")
	}
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	nested := writeActiveAgentTestFile(t, filepath.Join(project, "pkg", "deep"), "CLAUDE.md")
	alias := instructionIdentityTestLink(t, nested, filepath.Join(root, "elsewhere", "notes.txt"))
	for _, call := range instructionIdentityWrites(alias) {
		for source, ctx := range instructionIdentityContexts(t, project, call.tool, call.input) {
			api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
			api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "InstructionsLoaded", SessionID: "nested", CWD: project, FilePath: nested,
			})
			response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "nested", CWD: project, ToolName: call.tool, ToolInput: call.input,
			})
			if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, "COG-CLAUDE-MD") {
				t.Fatalf("%s through the unindexed hard link (%s): action=%q findings=%v", call.tool, source, response.Action, response.Findings)
			}
		}
	}
}

// GAP-1115 (decided: fixed at base by the GAP-0869/0971 identity proof). A
// symlink named alias to the project's AGENTS.md is judged as AGENTS.md:
// after a gateway restart that restored the session's snapshot it blocks by
// identity, and for a session the restarted gateway never saw it gets exactly
// the verdict of the direct name in each pack, never an allow.
func TestR105GAP1115InstructionAliasAfterRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlinks")
	}
	home := testenv.PrivateTempDir(t)
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	project := filepath.Join(home, "project")
	file := writeActiveAgentTestFile(t, project, "AGENTS.md")
	if err := os.Symlink(file, filepath.Join(project, "alias")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	before := newR105CodexRoute(t, home, "HIGH")
	before.start("restarted", project)
	after := newR105CodexRoute(t, home, "HIGH")
	if action, findings := after.bash("restarted", project, "printf changed >> alias"); action != guardrailActionBlock || !findingStringHasRuleID(findings, "COG-AGENTS-MD") {
		t.Fatalf("alias after restart: action=%q findings=%v", action, findings)
	}
	for _, pack := range []string{"default", "strict"} {
		fresh := newR105CodexRoute(t, home, "")
		fresh.api.scannerCfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
		direct, directFindings := fresh.bash("unseen-direct-"+pack, project, "printf changed >> AGENTS.md")
		aliased, aliasFindings := fresh.bash("unseen-alias-"+pack, project, "printf changed >> alias")
		if aliased != direct || aliased == "allow" || !findingStringHasRuleID(aliasFindings, "COG-AGENTS-MD") {
			t.Fatalf("%s pack, unseen session: direct=%q %v alias=%q %v", pack, direct, directFindings, aliased, aliasFindings)
		}
	}
}
