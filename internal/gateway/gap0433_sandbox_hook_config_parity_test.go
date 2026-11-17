// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap0433LaptopSettings is the ~/.claude/settings.json of a laptop with the
// Claude Code connector set up: its per-user setup registers DefenseClaw's
// hooks there.
const gap0433LaptopSettings = `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"~/.defenseclaw/hooks/claude-code-hook.sh","timeout":30}]}]}}`

// gap0433Verdict runs one Claude Code PreToolUse call and returns its action,
// severity and the catalog rule IDs its response names.
func gap0433Verdict(t *testing.T, api *APIServer, ctx context.Context, cwd, tool string, input map[string]any) (action, severity string, rules []string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "gap0433", "cwd": cwd,
		"tool_name": tool, "tool_input": input, "tool_use_id": t.Name(),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(response, req.WithContext(ctx))
	if response.Code != http.StatusOK {
		t.Fatalf("hook status=%d: %.500s", response.Code, response.Body.String())
	}
	var decoded struct {
		Action   string `json:"action"`
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("hook response: %v: %.500s", err, response.Body.String())
	}
	known := map[string]bool{}
	for _, category := range defaultRuleCategories() {
		for _, rule := range category.Rules {
			known[rule.ID] = true
		}
	}
	for _, word := range gap0264RuleIDPattern.FindAllString(response.Body.String(), -1) {
		if known[word] && !slices.Contains(rules, word) {
			rules = append(rules, word)
		}
	}
	slices.Sort(rules)
	return decoded.Action, decoded.Severity, rules
}

// GAP-0433 (substrate-1): in a Substrate actor a Claude Code Write of {} to
// ~/.claude/settings.json was allow/NONE while the laptop blocked it CRITICAL
// with tamper.agent_hook_config_disable. The laptop reads the file and sees
// the write drop the DefenseClaw hooks its setup registered there; the
// gateway cannot read the guest's file, so the actor judged the write against
// no file at all. Each call runs on a laptop whose ~/.claude/settings.json
// holds DefenseClaw's hooks and in a copy-mode and a mount-mode actor, and
// every actor verdict (action, severity, rules) must be the laptop's.
func TestGAP0433SandboxAgentHookConfigParityWithLaptop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	packDir := installDefaultRulePackForDataDir(t, t.TempDir())
	pack := mustLoadRulePack(t, packDir)
	installDefaultProfileConnector(t, "claudecode")
	if err := ApplyConnectorRulePackOverrides("claudecode", pack); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".claude"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(gap0433LaptopSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = packDir
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}

	actor := func(mounted bool) context.Context {
		binding := sandboxTestBinding("claudecode")
		if mounted {
			binding.Workdir = sandboxauth.Workdir{
				Mode:   sandboxauth.WorkdirMount,
				Mounts: []sandboxauth.Mount{{SandboxPath: gap0264ActorWorkdir, HostPath: project}},
			}
		}
		ctx := sandboxauth.WithRequest(context.Background(), binding, nil)
		ctx = withAuthenticatedHookConnector(ctx, binding.Connector)
		return withProfilePath(ctx, profilePathHook)
	}

	kept := strings.Replace(gap0433LaptopSettings, `{"hooks"`, `{"permissions":{"allow":["Read"]},"hooks"`, 1)
	probes := []struct {
		name, tool string
		input      map[string]any
		want       string // the laptop's action, pinned so the oracle stays a real one
	}{
		// The cert's J03 W5 prompt and its literal spellings.
		{"settings tilde Write {}", "Write", map[string]any{"file_path": "~/.claude/settings.json", "content": "{}"}, "block"},
		{"settings home Write {}", "Write", map[string]any{"file_path": "{H}/.claude/settings.json", "content": "{}"}, "block"},
		{"settings home Write unreadable", "Write", map[string]any{"file_path": "{H}/.claude/settings.json", "content": "{"}, "block"},
		{"settings home Write drops hooks", "Write", map[string]any{"file_path": "{H}/.claude/settings.json", "content": `{"permissions":{"allow":["Read"]}}`}, "block"},
		{"settings home Edit drops hook", "Edit", map[string]any{"file_path": "{H}/.claude/settings.json",
			"old_string": `"command":"~/.defenseclaw/hooks/claude-code-hook.sh"`, "new_string": `"command":"true"`}, "block"},
		{"settings home MultiEdit drops hook", "MultiEdit", map[string]any{"file_path": "~/.claude/settings.json",
			"edits": []any{map[string]any{"old_string": ".defenseclaw/hooks/claude-code-hook.sh", "new_string": "x.sh"}}}, "block"},
		{"settings home disableAllHooks", "Write", map[string]any{"file_path": "{H}/.claude/settings.json", "content": `{"disableAllHooks":true}`}, "block"},
		{"settings.local tilde disableAllHooks", "Write", map[string]any{"file_path": "~/.claude/settings.local.json", "content": `{"disableAllHooks":true}`}, "block"},
		{"settings.local home allowManagedHooksOnly", "Write", map[string]any{"file_path": "{H}/.claude/settings.local.json", "content": `{"allowManagedHooksOnly":true}`}, "block"},
		// Controls: a write that keeps the hooks, an Edit that does not touch
		// them, and a settings.local.json that never held them.
		{"settings home Write keeps hooks", "Write", map[string]any{"file_path": "{H}/.claude/settings.json", "content": kept}, "allow"},
		{"settings home Edit keeps hooks", "Edit", map[string]any{"file_path": "{H}/.claude/settings.json",
			"old_string": `"timeout":30`, "new_string": `"timeout":30`}, "allow"},
		{"settings.local tilde Write {}", "Write", map[string]any{"file_path": "~/.claude/settings.local.json", "content": "{}"}, "allow"},
		{"settings.local home Write {}", "Write", map[string]any{"file_path": "{H}/.claude/settings.local.json", "content": "{}"}, "allow"},
		{"project settings Write {}", "Write", map[string]any{"file_path": "{P}/.claude/settings.json", "content": "{}"}, "allow"},
	}
	for _, probe := range probes {
		t.Run(probe.name, func(t *testing.T) {
			laptopInput := gap0264Expand(probe.input, project, home).(map[string]any)
			actorInput := gap0264Expand(probe.input, gap0264ActorWorkdir, sandboxauth.SandboxHome).(map[string]any)
			lAction, lSeverity, lRules := gap0433Verdict(t, api, context.Background(), project, probe.tool, laptopInput)
			cAction, cSeverity, cRules := gap0433Verdict(t, api, actor(false), gap0264ActorWorkdir, probe.tool, actorInput)
			mAction, mSeverity, mRules := gap0433Verdict(t, api, actor(true), gap0264ActorWorkdir, probe.tool, actorInput)
			t.Logf("PARITY %-42s laptop=%s/%s %v copy=%s/%s %v mount=%s/%s %v", probe.name,
				lAction, lSeverity, lRules, cAction, cSeverity, cRules, mAction, mSeverity, mRules)
			if lAction != probe.want {
				t.Fatalf("laptop oracle %s/%s %v, want %s", lAction, lSeverity, lRules, probe.want)
			}
			if cAction != lAction || cSeverity != lSeverity || !slices.Equal(cRules, lRules) {
				t.Errorf("copy-mode actor %s/%s %v, laptop %s/%s %v", cAction, cSeverity, cRules, lAction, lSeverity, lRules)
			}
			if mAction != lAction || mSeverity != lSeverity || !slices.Equal(mRules, lRules) {
				t.Errorf("mount-mode actor %s/%s %v, laptop %s/%s %v", mAction, mSeverity, mRules, lAction, lSeverity, lRules)
			}
		})
	}
}
