// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
func TestGAP0433SandboxAgentHookConfigParityWithLaptop(t *testing.T) { gapNF6Parity(t) }

type gapNF6ParityRow struct {
	name, tool                  string
	input                       map[string]any
	want, file, actor           string
	target, noCopy, mountNoCopy string
}

func gapNF6Parity(t *testing.T) { gapNF6ParityModes(t, true) }

func gapNF6ParityModes(t *testing.T, withFacts bool) {
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
		// GAP-0536 (RKNF review of the GAP-0433 fix): changes the actor
		// judged without the file's DefenseClaw entries. The actor applies
		// them to the exact kit snapshot and compares as the laptop does;
		// absent snapshots use the shared ambiguity refusal.
		{"rknf Edit keeps old as substring", "Edit", map[string]any{"file_path": "{H}/.claude/settings.json",
			"old_string": "~/.defenseclaw/hooks/claude-code-hook.sh", "new_string": "true || ~/.defenseclaw/hooks/claude-code-hook.sh"}, "block"},
		{"rknf Edit renames hooks key", "Edit", map[string]any{"file_path": "{H}/.claude/settings.json",
			"old_string": `{"hooks":`, "new_string": `{"hooks_off":`}, "block"},
		{"rknf Edit renames PreToolUse", "Edit", map[string]any{"file_path": "{H}/.claude/settings.json",
			"old_string": `"PreToolUse"`, "new_string": `"PreToolUseOff"`}, "block"},
		{"rknf Write decoy hook", "Write", map[string]any{"file_path": "{H}/.claude/settings.json",
			"content": `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"echo defenseclaw"}]}]}}`}, "block"},
		{"rknf Write dotdot path", "Write", map[string]any{"file_path": "{H}/.claude/../.claude/settings.json", "content": "{}"}, "block"},
		// The same rule for other spellings: a case change of the event key,
		// a later duplicate hooks key that overrides the kept one, and a
		// matcher change.
		{"gap0536 Edit lower-cases PreToolUse", "Edit", map[string]any{"file_path": "~/.claude/settings.json",
			"old_string": `"PreToolUse"`, "new_string": `"pretooluse"`}, "block"},
		{"gap0536 Edit adds later hooks key", "Edit", map[string]any{"file_path": "{H}/.claude/settings.json",
			"old_string": `"timeout":30}]}]}}`, "new_string": `"timeout":30}]}]},"hooks":{}}`}, "block"},
		{"gap0536 MultiEdit narrows matcher", "MultiEdit", map[string]any{"file_path": "{H}/.claude/settings.json",
			"edits": []any{map[string]any{"old_string": `"matcher":"*"`, "new_string": `"matcher":"Read"`}}}, "block"},
		// Controls: a write that keeps the hooks, an Edit that does not touch
		// them, and a settings.local.json that never held them. A missing
		// snapshot cannot prove that last fact, so replacements then refuse.
		{"settings home Write keeps hooks", "Write", map[string]any{"file_path": "{H}/.claude/settings.json", "content": kept}, "allow"},
		{"settings home Edit keeps hooks", "Edit", map[string]any{"file_path": "{H}/.claude/settings.json",
			"old_string": `"timeout":30`, "new_string": `"timeout":30`}, "allow"},
		{"settings.local tilde Write {}", "Write", map[string]any{"file_path": "~/.claude/settings.local.json", "content": "{}"}, "allow"},
		{"settings.local home Write {}", "Write", map[string]any{"file_path": "{H}/.claude/settings.local.json", "content": "{}"}, "allow"},
		{"project settings Write {}", "Write", map[string]any{"file_path": "{P}/.claude/settings.json", "content": "{}"}, "allow"},
	}
	type parityRow = gapNF6ParityRow
	// GAP-0577 (RKNF2 review of the GAP-0536 fix): an Edit or MultiEdit that
	// could not be judged from the former guessed originals, because the
	// laptop file holds another key or layout, was allow/NONE in the actor
	// and block/CRITICAL on the laptop. Each row sets its own laptop file.
	withModel := strings.Replace(gap0433LaptopSettings, `{"hooks"`, `{"model":"zzz","hooks"`, 1)
	spaced := strings.Replace(gap0433LaptopSettings, `"PreToolUse":[`, `"PreToolUse" :[`, 1)
	spacedModel := strings.Replace(spaced, `{"hooks"`, `{"model":"zzz","hooks"`, 1)
	spacedPath := strings.Replace(gap0433LaptopSettings, `.sh","timeout"`, `.sh" ,"timeout"`, 1)
	withEnv := strings.Replace(gap0433LaptopSettings, `{"hooks"`, `{"env":{"A":"1"},"model":"zzz","permissions":{"allow":["Read"]},"hooks"`, 1)
	withStatus := strings.Replace(gap0433LaptopSettings, `{"hooks"`, `{"statusLine":{"type":"command","command":"a.sh"},"hooks"`, 1)
	settings := "{H}/.claude/settings.json"
	// Round 2 (RVNF2 review of the round-1 fix): laptop files the earlier
	// rows do not set up.
	escKey := strings.Replace(withModel, `"PreToolUse"`, `"Pre\u0054oolUse"`, 1)
	escPath := strings.Replace(withModel, `claude-code-hook.sh`, `claude-code-hook\u002esh`, 1)
	withNode := strings.Replace(gap0433LaptopSettings, `{"hooks"`, `{"env":{"NODE_OPTIONS":"--max-old-space-size=4096"},"model":"zzz","hooks"`, 1)
	withSwitch := strings.Replace(gap0433LaptopSettings, `{"hooks"`, `{"disableAllHooks":false,"model":"zzz","hooks"`, 1)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, []byte(withModel), "", "  "); err != nil {
		t.Fatal(err)
	}
	gap0577 := []parityRow{
		// The RKNF2 probes: one call with an extra "model" edit, and the
		// two-call chains (a layout or key the copies lack, then the change).
		{name: "gap0577 one-call MultiEdit timeout + model", file: withModel, tool: "MultiEdit", want: "block", input: map[string]any{"file_path": settings, "edits": []any{
			map[string]any{"old_string": `"timeout":30`, "new_string": `"timeout":0`},
			map[string]any{"old_string": `"model":"zzz"`, "new_string": `"model":"y"`}}}},
		{name: "gap0577 chain 1 Write adds model", tool: "Write", want: "allow", input: map[string]any{"file_path": settings, "content": withModel}},
		{name: "gap0577 chain 2 MultiEdit renames PreToolUse + model", file: withModel, tool: "MultiEdit", want: "block", input: map[string]any{"file_path": settings, "edits": []any{
			map[string]any{"old_string": `"PreToolUse"`, "new_string": `"PreToolUseOff"`},
			map[string]any{"old_string": `"zzz"`, "new_string": `"zzy"`}}}},
		{name: "gap0577 chain 2 MultiEdit narrows matcher + model", file: withModel, tool: "MultiEdit", want: "block", input: map[string]any{"file_path": "~/.claude/settings.json", "edits": []any{
			map[string]any{"old_string": `"matcher":"*"`, "new_string": `"matcher":"Read"`},
			map[string]any{"old_string": `"zzz"`, "new_string": `"zzy"`}}}},
		{name: "gap0577 chain 1 Edit spaces PreToolUse", tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `"PreToolUse":[`, "new_string": `"PreToolUse" :[`}},
		{name: "gap0577 chain 2 Edit renames spaced PreToolUse", file: spaced, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"PreToolUse" :[`, "new_string": `"PreToolUseOff" :[`}},
		{name: "gap0577 chain 2 Edit narrows spaced matcher", file: spaced, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"PreToolUse" :[{"matcher":"*"`, "new_string": `"PreToolUse" :[{"matcher":"Read"`}},
		// The same class in other spellings: a fragment of the key, text
		// appended to it, a fragment of the hook path, a file left unreadable,
		// a reserved hook process variable and disableAllHooks beside another
		// key.
		{name: "gap0577 Edit renames spaced key fragment", file: spaced, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `ToolUse" :[`, "new_string": `ToolUseOff" :[`}},
		{name: "gap0577 Edit appends to spaced key", file: spaced, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `" :[`, "new_string": `Off" :[`}},
		{name: "gap0577 Edit changes spaced hook path tail", file: spacedPath, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `.sh" ,`, "new_string": `.shx" ,`}},
		{name: "gap0577 Edit leaves the file unreadable", file: withModel, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"model":"zzz"`, "new_string": `"model":"zzz",,`}},
		{name: "gap0577 Edit sets a reserved env", file: withEnv, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"A":"1"`, "new_string": `"A":"1","BASH_ENV":"/tmp/x"`}},
		{name: "gap0577 Edit adds disableAllHooks beside model", file: withModel, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"model":"zzz"`, "new_string": `"model":"zzz","disableAllHooks":true`}},
		// Controls: edits that name no hook key keep the laptop's verdict.
		{name: "gap0577 Edit changes model beside hooks", file: withModel, tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `"model":"zzz"`, "new_string": `"model":"claude-sonnet"`}},
		{name: "gap0577 Edit changes a value only", file: withModel, tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `"zzz"`, "new_string": `"claude-opus"`}},
		{name: "gap0577 MultiEdit model + permission", file: withEnv, tool: "MultiEdit", want: "allow", input: map[string]any{"file_path": settings, "edits": []any{
			map[string]any{"old_string": `"model":"zzz"`, "new_string": `"model":"y"`},
			map[string]any{"old_string": `"allow":["Read"]`, "new_string": `"allow":["Read","Bash(npm run typecheck)"]`}}}},
		{name: "gap0577 Edit env value", file: withEnv, tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `"A":"1"`, "new_string": `"A":"2"`}},
		{name: "gap0577 Edit adds NODE_OPTIONS memory", file: withEnv, tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `"A":"1"`, "new_string": `"A":"1","NODE_OPTIONS":"--max-old-space-size=4096"`}},
		{name: "gap0577 Edit changes model in spaced file", file: spacedModel, tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `"model":"zzz"`, "new_string": `"model":"y"`}},
		// Stricter by the lead's ruling: a statusLine command names the keys
		// the hook entries are written with, so the actor cannot tell it
		// from theirs.
		{name: "gap0577 Edit statusLine command (stricter)", file: withStatus, tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `"command":"a.sh"`, "new_string": `"command":"b.sh"`}},
		// Round 2, F1: a \u escape spells a hook key, the hook path, a
		// reserved env name or a hooks switch.
		{name: "gap0577 Edit renames escaped PreToolUse", file: escKey, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"Pre\u0054oolUse"`, "new_string": `"Pre\u0054oolUseOff"`}},
		{name: "gap0577 Edit changes escaped hook path", file: escPath, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `hook\u002esh"`, "new_string": `hook\u002eshx"`}},
		{name: "gap0577 Edit adds escaped BASH_ENV", file: withEnv, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"A":"1"`, "new_string": `"A":"1","BASH\u005fENV":"/tmp/x"`}},
		{name: "gap0577 Edit adds escaped allowManagedHooksOnly", file: withModel, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"zzz"`, "new_string": `"zzz","allow\u004danagedHooksOnly":true,"x":"y"`}},
		// F2: a reserved hook process variable set without a whole pair.
		{name: "gap0577 Edit NODE_OPTIONS value preloads", file: withNode, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `--max-old-space-size=4096`, "new_string": `--require=/tmp/x.js`}},
		{name: "gap0577 Edit renames env key to BASH_ENV", file: withEnv, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"A"`, "new_string": `"BASH_ENV"`}},
		// F3: an edit of a value or fragment that leaves the file unreadable.
		{name: "gap0577 Edit value to open array", file: withModel, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"zzz"`, "new_string": `["zzz"`}},
		{name: "gap0577 Edit value double comma", file: withModel, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"zzz",`, "new_string": `"zzz",,`}},
		{name: "gap0577 Edit string tail stray quote", file: withModel, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `zzz`, "new_string": `zzz"`}},
		{name: "gap0577 Edit value stray bracket", file: withModel, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `"zzz"`, "new_string": `"zzz"]`}},
		// F4: a hooks switch flipped by an edit that starts at its value.
		{name: "gap0577 Edit flips disableAllHooks before model", file: withSwitch, tool: "Edit", want: "block", input: map[string]any{"file_path": settings,
			"old_string": `false,"model"`, "new_string": `true,"model"`}},
		// F6: benign edits that name no hook key keep the laptop's verdict.
		{name: "gap0577 Edit adds includeCoAuthoredBy", file: withModel, tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `"model":"zzz"`, "new_string": `"model":"zzz","includeCoAuthoredBy":false`}},
		{name: "gap0577 Edit pretty adds alwaysThinkingEnabled", file: pretty.String(), tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `"model": "zzz"`, "new_string": "\"model\": \"zzz\",\n  \"alwaysThinkingEnabled\": true"}},
		{name: "gap0577 Edit adds env number", file: withEnv, tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `"A":"1"`, "new_string": `"A":"1","B":2`}},
		{name: "gap0577 Edit number only", file: withNode, tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `4096`, "new_string": `8192`}},
		{name: "gap0577 Edit nested env is not env", file: withModel, tool: "Edit", want: "allow", input: map[string]any{"file_path": settings,
			"old_string": `"model":"zzz"`, "new_string": `"model":"zzz","x":{"env":{"LD_LIBRARY_PATH":"/opt"}}`}},
		// F7: an edit the laptop's file does not hold is refused there and
		// alerted on its text.
		{name: "gap0577 Edit enabledPlugins not in file", tool: "Edit", want: "alert", input: map[string]any{"file_path": settings,
			"old_string": `"enabledPlugins":{"a@b":true}`, "new_string": `"enabledPlugins":{}`}},
		{name: "gap0577 Edit hooksDisabled not in file", tool: "Edit", want: "alert", input: map[string]any{"file_path": settings,
			"old_string": `"hooksDisabled":false`, "new_string": `"hooksDisabled":true`}},
		// GAP-0578 (a): inline code that writes the registered file.
		{name: "gap0578 Bash python -c writes settings", tool: "Bash", want: "alert", input: map[string]any{
			"command": `python3 -c "open('{H}/.claude/settings.json','w').write('{}')"`}},
	}
	// RVNF5 cases are retained verbatim, including controls and invalid JSON.
	base, model := gap0433LaptopSettings, withModel
	with := func(member string) string { return "{" + member + "," + base[1:] }
	rvnf5 := []struct{ name, file, old, new string }{
		{"switch_leading_space", with(`"disableAllHooks": false,"model":"zzz"`), ` false,"model"`, ` true,"model"`},
		{"switch_space_only", with(`"disableAllHooks": false`), " false", " true"},
		{"switch_pretty_newline", with("\"disableAllHooks\":\n    false"), "\n    false", "\n    true"},
		{"escape_hex_key", strings.Replace(model, "PreToolUse", `Pre\u0054oolUse`, 1), "0054", "0058"},
		{"escape_hex_path", strings.Replace(model, "hook.sh", `hook\u002esh`, 1), "002e", "002f"},
		{"escape_hex_model_benign", with(`"model":"z\u007az"`), "007a", "0079"},
		{"escape_benign_model", model, `"zzz"`, `"zz\u007a"`},
		{"C20_LD_value", with(`"env":{"LD_LIBRARY_PATH":"/opt/lib"}`), `"/opt/lib"`, `"/tmp/evil"`},
		{"C20_NODE_path", with(`"env":{"NODE_OPTIONS":"--require=/opt/good.js"}`), "/opt/good.js", "/tmp/evil.js"},
		{"C20_BASH_ENV", with(`"env":{"BASH_ENV":"/opt/good.sh"}`), "/opt/good.sh", "/tmp/evil.sh"},
		{"NODE_full_quoted_value", with(`"env":{"NODE_OPTIONS":"--max-old-space-size=4096"}`), `"--max-old-space-size=4096"`, `"--require=/tmp/x.js"`},
		{"NODE_split_flag", with(`"env":{"NODE_OPTIONS":"--max-old-space-size=4096"}`), "max-old-space-size=4096", "require=/tmp/x.js"},
		{"NODE_split_argument", with(`"env":{"NODE_OPTIONS":"--require= --max-old-space-size=4096"}`), " --max-old-space-size=4096", "/tmp/x.js"},
		{"benign_model_boolean_string", with(`"model":"false"`), "false", "true"},
		{"benign_model_name_null", with(`"model":"null-model"`), "null-model", "new-model"},
		{"benign_model_number", with(`"model":"v30"`), "30", "60"},
		{"benign_allow_option", with(`"alwaysThinkingEnabled":false`), "false", "true"},
		{"benign_boolean_member", with(`"alwaysThinkingEnabled":false`), `"alwaysThinkingEnabled":false`, `"alwaysThinkingEnabled":true`},
		{"benign_model_reserved_word", model, `"zzz"`, `"LD_LIBRARY_PATH"`},
		{"benign_model_loader", model, "zzz", "--require=/tmp/x.js"},
		{"unreadable_boolean_string", with(`"model":"false"`), "false", "true,"},
		{"unreadable_escape", with(`"model":"a\\b"`), `a\\b`, `a\b`},
		{"unreadable_array", with(`"x":["zzz"]`), `"zzz"`, `"zzz","x":1`},
		{"unreadable_array_value", with(`"x":["zzz"]`), `zzz`, `zzz","x":1,"j":"y`},
	}
	for _, row := range rvnf5 {
		want := "block"
		if strings.Contains(row.name, "benign") || row.name == "unreadable_boolean_string" || row.name == "unreadable_escape" {
			want = "allow"
		}
		gap0577 = append(gap0577, parityRow{name: "rvnf5 " + row.name, file: row.file, tool: "Edit", want: want,
			input: map[string]any{"file_path": settings, "old_string": row.old, "new_string": row.new}})
	}
	rows := make([]parityRow, 0, len(probes)+len(gap0577))
	for _, probe := range probes {
		row := parityRow{name: probe.name, tool: probe.tool, input: probe.input, want: probe.want}
		if probe.tool == "Write" && probe.want == "allow" && probe.input["content"] == "{}" {
			row.noCopy = "block"
			if strings.HasPrefix(probe.input["file_path"].(string), "{P}/") {
				// The confined mount view proves this project file absent.
				row.mountNoCopy = "allow"
			}
		}
		rows = append(rows, row)
	}

	for _, n := range []int{64, 65, 4000} {
		edits := make([]any, n)
		for i := range edits {
			edits[i] = map[string]any{"old_string": `"timeout":30`, "new_string": `"timeout":30`}
		}
		stricter := ""
		if n > 64 {
			stricter = "block"
		}
		want := "allow"
		if n == 4000 {
			want = "block"
		}
		gap0577 = append(gap0577, parityRow{name: fmt.Sprintf("rvnf5 count bound %d", n), tool: "MultiEdit", want: want, actor: stricter, input: map[string]any{"file_path": settings, "edits": edits}})
	}
	for _, n := range []int{65536, 65537, 131072} {
		gap0577 = append(gap0577, parityRow{name: fmt.Sprintf("rvnf5 text bound %d", n), tool: "Edit", want: "allow", actor: "block", input: map[string]any{
			"file_path": settings, "old_string": `{"hooks"`, "new_string": `{"model":"` + strings.Repeat("p", n) + `","hooks"`}})
	}
	for _, n := range []int{8, 12, 16} {
		edits := []any{map[string]any{"old_string": `{"hooks"`, "new_string": `{"model":"ZZ","hooks"`}}
		for i := 0; i < n; i++ {
			edits = append(edits, map[string]any{"old_string": "ZZ", "new_string": "ZZZZ", "replace_all": true})
		}
		stricter := ""
		if n == 16 {
			stricter = "block"
		}
		gap0577 = append(gap0577, parityRow{name: fmt.Sprintf("rvnf5 expansion bound %d", n), tool: "MultiEdit", want: "allow", actor: stricter, input: map[string]any{"file_path": settings, "edits": edits}})
	}

	gap0577 = append(gap0577,
		parityRow{name: "nf6 prefix switch then restore", file: withSwitch, tool: "MultiEdit", want: "allow", input: map[string]any{"file_path": settings, "edits": []any{
			map[string]any{"old_string": `"disableAllHooks":false`, "new_string": `"disableAllHooks":true`},
			map[string]any{"old_string": `"disableAllHooks":true`, "new_string": `"disableAllHooks":false`},
		}}},
		parityRow{name: "nf6 unapplicable suffix", tool: "MultiEdit", want: "alert", input: map[string]any{"file_path": settings, "edits": []any{
			map[string]any{"old_string": `"timeout":30`, "new_string": `"timeout":30`},
			map[string]any{"old_string": `"hooksDisabled":false`, "new_string": `"hooksDisabled":true`},
		}}},
	)
	gap0577 = append(gap0577, parityRow{
		name: "nf7 ambiguous LD-vs-model value", file: with(`"model":"/opt/lib"`), tool: "Edit", want: "allow",
		input: map[string]any{"file_path": settings, "old_string": `"/opt/lib"`, "new_string": `"/tmp/evil"`},
	})
	rows = append(rows, gap0577...)
	rows = append(rows, gapNF8ReviewRows()...)
	for _, probe := range rows {
		t.Run(probe.name, func(t *testing.T) {
			file := probe.file
			if file == "" && probe.target == "" {
				file = gap0433LaptopSettings
			}
			for _, rel := range []string{".claude/settings.local.json", "proj/.claude/settings.json", "proj/.claude/settings.local.json"} {
				if err := os.Remove(filepath.Join(home, rel)); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(file), 0o600); err != nil {
				t.Fatal(err)
			}
			if probe.target != "" {
				target := filepath.Join(home, probe.target)
				if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte(file), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			laptopInput := gap0264Expand(probe.input, project, home).(map[string]any)
			actorInput := gap0264Expand(probe.input, gap0264ActorWorkdir, sandboxauth.SandboxHome).(map[string]any)
			lAction, lSeverity, lRules := gap0433Verdict(t, api, context.Background(), project, probe.tool, laptopInput)
			copyCtx, mountCtx := actor(false), actor(true)
			if withFacts {
				target, _ := actorInput["file_path"].(string)
				if target == "" {
					target = sandboxauth.SandboxHome + "/.claude/settings.json"
				}
				target = strings.Replace(target, "~", sandboxauth.SandboxHome, 1)
				before := file
				if probe.target == "" && (strings.HasSuffix(target, "/settings.local.json") || strings.HasPrefix(target, gap0264ActorWorkdir+"/")) {
					before = ""
				}
				copyCtx, mountCtx = gapNF8Facts(copyCtx, target, before), gapNF8Facts(mountCtx, target, before)
			}
			cAction, cSeverity, cRules := gap0433Verdict(t, api, copyCtx, gap0264ActorWorkdir, probe.tool, actorInput)
			mAction, mSeverity, mRules := gap0433Verdict(t, api, mountCtx, gap0264ActorWorkdir, probe.tool, actorInput)
			t.Logf("PARITY %-42s laptop=%s/%s %v copy=%s/%s %v mount=%s/%s %v", probe.name,
				lAction, lSeverity, lRules, cAction, cSeverity, cRules, mAction, mSeverity, mRules)
			gapNF6Probe(t, fmt.Sprintf("%s/facts=%t", probe.name, withFacts), file, probe.input, lAction+"/"+lSeverity+"/"+strings.Join(lRules, ","), cAction+"/"+cSeverity+"/"+strings.Join(cRules, ",")+";"+mAction+"/"+mSeverity+"/"+strings.Join(mRules, ","))
			if lAction != probe.want {
				t.Fatalf("laptop oracle %s/%s %v, want %s", lAction, lSeverity, lRules, probe.want)
			}
			// These Writes keep the one-entry fallback document the laptop
			// file holds here, not what Setup writes: without a snapshot the
			// actor requires Setup's full hook set (substrate-1 GAP-0615; the
			// real-setup row is TestGAP0615GuestHookConfigParity
			// C1_control_Write_keeps_all_hooks).
			if probe.noCopy == "" && (probe.name == "settings home Write keeps hooks" || probe.name == "gap0577 chain 1 Write adds model") {
				probe.noCopy = "block"
			}
			if !withFacts && (probe.tool == "Edit" || probe.tool == "MultiEdit" || probe.noCopy != "") {
				expected := "block"
				if probe.name == "settings home Edit keeps hooks" || probe.name == "rvnf5 count bound 64" || probe.name == "rvnf5 escape_benign_model" {
					expected = "allow"
				}
				if probe.noCopy != "" {
					expected = probe.noCopy
				}
				mountExpected := expected
				if probe.mountNoCopy != "" {
					mountExpected = probe.mountNoCopy
				}
				if cAction != expected || mAction != mountExpected {
					t.Errorf("no-copy: copy=%s mount=%s, want %s/%s (T6 ambiguity ruling; exact mount facts win)", cAction, mAction, expected, mountExpected)
				}
				if expected == "block" && cSeverity != "CRITICAL" || mountExpected == "block" && mSeverity != "CRITICAL" {
					t.Errorf("ambiguous edits must be CRITICAL, copy=%s mount=%s", cSeverity, mSeverity)
				}
				return
			}
			if probe.actor != "" {
				if cAction != probe.actor || mAction != probe.actor {
					t.Errorf("actor copy=%s mount=%s, want the stricter %s", cAction, mAction, probe.actor)
				}
				return
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
