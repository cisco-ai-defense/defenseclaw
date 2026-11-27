// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap0615Verdict posts one PreToolUse call to the connector's hook route and
// returns action/severity and the body.
func gap0615Verdict(t *testing.T, api *APIServer, ctx context.Context, connector, cwd, tool string, input map[string]any) (string, string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0615", "cwd": cwd, "tool_name": tool, "tool_input": input, "tool_use_id": t.Name()})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	rec := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d %.1000s", rec.Code, rec.Body.String())
	}
	var v struct {
		Action   string `json:"action"`
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || v.Action == "" {
		t.Fatalf("no verdict: %v %.1000s", err, rec.Body.String())
	}
	return v.Action + "/" + v.Severity, rec.Body.String()
}

// gap0615KitFacts is what the actor kit sends for a native file tool call on
// a settings path (kit attachAgentHookBefore): the path fact, with the file
// a link reaches, and, unless before is nil, the exact pre-edit snapshot
// keyed by the name the call used.
func gap0615KitFacts(ctx context.Context, name, reached string, before *string) context.Context {
	facts := &SubstrateFacts{Paths: []SubstratePathFact{{Field: "tool_input.file_path", Path: name, Abs: name, Resolved: reached, Type: "file"}}}
	if before != nil {
		sum := sha256.Sum256([]byte(*before))
		facts.Files = []SubstrateAttachedFile{{Role: "agent_hook_config_before", Path: name, Resolved: reached,
			Content: []byte(*before), Size: int64(len(*before)), SHA256: hex.EncodeToString(sum[:])}}
	}
	return context.WithValue(ctx, substrateEnvelopeKey{}, substrateEnvelope{Facts: facts})
}

// TestGAP0615GuestHookConfigParity is the RVNF8B parity probe (substrate-1
// GAP-0615..0620) on settings Setup really writes (every installed event):
// each row asserts the actor's action and severity equal the laptop's for
// the same file operation. The actor's document names the guest home where
// the laptop's names the laptop home, as Setup in the guest would write it.
// "nokit" actors send no file facts (no snapshot, no link facts); "kit"
// actors send what the current kit sends.
func TestGAP0615GuestHookConfigParity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run as the unprivileged build user")
	}
	packDir := installDefaultRulePackForDataDir(t, t.TempDir())
	pack := mustLoadRulePack(t, packDir)
	for _, c := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, c)
		if err := ApplyConnectorRulePackOverrides(c, pack); err != nil {
			t.Fatal(err)
		}
	}
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	opts := gatewayconnector.SetupOpts{DataDir: filepath.Join(home, ".defenseclaw"), APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000", AgentVersion: "2.1.270"}
	if err := gatewayconnector.NewClaudeCodeConnector().Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	installedBytes, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	installed := string(installedBytes)
	var doc map[string]any
	if err := json.Unmarshal(installedBytes, &doc); err != nil {
		t.Fatal(err)
	}
	hooks := doc["hooks"].(map[string]any)
	if len(hooks) < 5 || !strings.Contains(installed, home+"/.defenseclaw/hooks/claude-code-hook.sh") {
		t.Fatalf("setup did not register the absolute per-user hook on the full event set: %d events", len(hooks))
	}
	keptPre, _ := json.Marshal(map[string]any{"hooks": map[string]any{"PreToolUse": hooks["PreToolUse"]}})
	doc["model"] = "gap0615-before"
	keptAllBytes, _ := json.Marshal(doc)
	keptAll := string(keptAllBytes)
	guest := func(text string) string { return strings.ReplaceAll(text, home, sandboxauth.SandboxHome) }

	rename := map[string]any{"old_string": `"PreToolUse":`, "new_string": `"PreToolUseOff":`}
	model := map[string]any{"old_string": "gap0615-before", "new_string": "gap0615-after"}
	create := map[string]any{"old_string": "", "new_string": `{"model":"gap0615-after"}`}
	type row struct {
		name, connector, file, tool, want string
		missing, alias, kit, snapshot     bool
		input                             map[string]any
	}
	rows := []row{
		// GAP-0615: a replacement that keeps one PreToolUse entry drops the other installed events.
		{name: "C1_Write_single_fallback_PreToolUse", connector: "claudecode", file: installed, tool: "Write", want: "block", input: map[string]any{"content": gap0433LaptopSettings}},
		{name: "C1_Write_retains_only_PreToolUse", connector: "claudecode", file: installed, tool: "Write", want: "block", input: map[string]any{"content": string(keptPre)}},
		// GAP-0619: a replacement that keeps every installed hook (Setup's absolute command).
		{name: "C1_control_Write_keeps_all_hooks", connector: "claudecode", file: installed, tool: "Write", want: "allow", input: map[string]any{"content": keptAll}},
		{name: "C1_control_Write_keeps_all_hooks_kit", connector: "claudecode", file: installed, kit: true, snapshot: true, tool: "Write", want: "allow", input: map[string]any{"content": keptAll}},
		// GAP-0616: a Codex call on Claude's settings.
		{name: "C2_Codex_Write_drops_Claude_hooks", connector: "codex", file: installed, tool: "Write", want: "block", input: map[string]any{"content": "{}"}},
		{name: "C2_Codex_Edit_drops_Claude_hooks", connector: "codex", file: keptAll, tool: "Edit", want: "block", input: rename},
		{name: "C2_Codex_MultiEdit_drops_Claude_hooks", connector: "codex", file: keptAll, tool: "MultiEdit", want: "block", input: map[string]any{"edits": []any{rename, model}}},
		{name: "C2_Codex_Edit_drops_Claude_hooks_kit", connector: "codex", file: keptAll, kit: true, snapshot: true, tool: "Edit", want: "block", input: rename},
		{name: "C2_Codex_control_model_Edit_kit", connector: "codex", file: keptAll, kit: true, snapshot: true, tool: "Edit", want: "allow", input: model},
		// GAP-0617: an Edit that creates the file has a known result.
		{name: "C3_missing_Edit_create_benign", connector: "claudecode", missing: true, tool: "Edit", want: "allow", input: create},
		{name: "C3_empty_Edit_create_benign", connector: "claudecode", tool: "Edit", want: "allow", input: create},
		{name: "C3_missing_MultiEdit_create_benign", connector: "claudecode", missing: true, tool: "MultiEdit", want: "allow", input: map[string]any{"edits": []any{create, map[string]any{"old_string": "gap0615-after", "new_string": "gap0615-later"}}}},
		{name: "C3_missing_Edit_create_disable", connector: "claudecode", missing: true, tool: "Edit", want: "block", input: map[string]any{"old_string": "", "new_string": `{"disableAllHooks":true}`}},
		{name: "C3_empty_Edit_create_benign_with_snapshot", connector: "claudecode", kit: true, snapshot: true, tool: "Edit", want: "allow", input: create},
		// GAP-0618: a project link to the user settings, as the kit reports it.
		{name: "C4_symlink_Write_drops_hooks_kit", connector: "claudecode", file: installed, alias: true, kit: true, snapshot: true, tool: "Write", want: "block", input: map[string]any{"content": "{}"}},
		{name: "C4_symlink_Edit_drops_hooks_kit", connector: "claudecode", file: keptAll, alias: true, kit: true, snapshot: true, tool: "Edit", want: "block", input: rename},
		{name: "C4_symlink_control_model_Edit_kit", connector: "claudecode", file: keptAll, alias: true, kit: true, snapshot: true, tool: "Edit", want: "allow", input: model},
		{name: "C4_symlink_Write_drops_hooks_link_facts_only", connector: "claudecode", file: installed, alias: true, kit: true, tool: "Write", want: "block", input: map[string]any{"content": "{}"}},
		{name: "C4_symlink_Edit_drops_hooks_link_facts_only", connector: "claudecode", file: keptAll, alias: true, kit: true, tool: "Edit", want: "block", input: rename},
		// GAP-0620: the model Edit with the snapshot the kit sends.
		{name: "control_model_Edit_with_snapshot", connector: "claudecode", file: keptAll, kit: true, snapshot: true, tool: "Edit", want: "allow", input: model},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if r.missing {
				if err := os.Remove(settings); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(settings, []byte(r.file), 0o600); err != nil {
				t.Fatal(err)
			}
			laptopPath := settings
			guestSettings := sandboxauth.SandboxHome + "/.claude/settings.json"
			actorPath, reached := guestSettings, ""
			if r.alias {
				laptopPath = filepath.Join(project, "review-settings.json")
				_ = os.Remove(laptopPath)
				if err := os.Symlink(settings, laptopPath); err != nil {
					t.Fatal(err)
				}
				actorPath, reached = gap0264ActorWorkdir+"/review-settings.json", guestSettings
			}
			li, ai := map[string]any{"file_path": laptopPath}, map[string]any{"file_path": actorPath}
			for k, v := range r.input {
				li[k] = v
				if text, ok := v.(string); ok {
					v = guest(text)
				}
				ai[k] = v
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = r.connector
			cfg.Guardrail.RulePackDir = packDir
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			ctx := sandboxauth.WithRequest(context.Background(), sandboxTestBinding(r.connector), nil)
			ctx = withAuthenticatedHookConnector(ctx, r.connector)
			ctx = withProfilePath(ctx, profilePathHook)
			if r.kit {
				var before *string
				if r.snapshot {
					text := guest(r.file)
					before = &text
				}
				ctx = gap0615KitFacts(ctx, actorPath, reached, before)
			}
			laptop, lb := gap0615Verdict(t, api, context.Background(), r.connector, project, r.tool, li)
			actor, ab := gap0615Verdict(t, api, ctx, r.connector, gap0264ActorWorkdir, r.tool, ai)
			t.Logf("PARITY %s laptop=%s actor=%s", r.name, laptop, actor)
			if strings.Split(laptop, "/")[0] != r.want {
				t.Errorf("laptop oracle=%s want=%s: %.600s", laptop, r.want, lb)
			}
			if actor != laptop {
				t.Errorf("actor verdict %s != laptop verdict %s: %.600s", actor, laptop, ab)
			}
		})
	}
}

// TestGAP0620NoSnapshotEditStaysRefused pins the no-snapshot design: an Edit
// of Claude's settings that is not a create, from an actor that sent no
// snapshot (no kit), is refused on every connector with the kit next step,
// since a fragment without its document can be a hook or reserved env value.
func TestGAP0620NoSnapshotEditStaysRefused(t *testing.T) {
	for _, edits := range [][]agentHookConfigTextEdit{
		{{old: "gap0615-before", new: "gap0615-after"}},
		{{old: `"PreToolUse":`, new: `"PreToolUseOff":`}},
		{{old: "30", new: "1"}},
	} {
		change := agentHookConfigEditChange(sandboxauth.SandboxHome+"/.claude/settings.json", edits)
		if got := sandboxAgentHookWithoutBefore(gatewayconnector.AgentHookConfigClaudeSettings, change, sandboxauth.SandboxHome); got != sandboxAgentHookNoBefore {
			t.Fatalf("%+v: %q", edits, got)
		}
	}
}
