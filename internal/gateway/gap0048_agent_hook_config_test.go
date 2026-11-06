// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap0048Home lays out a per-user home with the hook files the per-user
// setups write, a project with its own Claude Code settings, and links
// outside the home that reach both.
type gap0048Home struct {
	home, project, ext string
	userSettings       string
}

const gap0048ClaudeUser = `{
  "model": "sonnet",
  "env": {"FOO": "1"},
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/home/u/.defenseclaw/bin/defenseclaw-hook-post", "timeout": 30}]}
    ],
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "/home/u/.defenseclaw/bin/defenseclaw-hook-user"}]}
    ]
  }
}
`

const gap0048CodexConfig = `model = "gpt-5"

[features]
hooks = true

[[hooks.PreToolUse]]
matcher = "*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/home/u/.defenseclaw/hooks/codex-hook.sh"
`

const gap0048Bridge = "// DefenseClaw OpenCode bridge\nexport const DefenseClaw = async () => ({})\n"

func newGAP0048Home(t *testing.T) gap0048Home {
	t.Helper()
	root := t.TempDir()
	h := gap0048Home{home: filepath.Join(root, "home"), ext: filepath.Join(root, "ext")}
	h.project = filepath.Join(h.home, "proj")
	h.userSettings = filepath.Join(h.home, ".claude", "settings.json")
	files := map[string]string{
		h.userSettings: gap0048ClaudeUser,
		filepath.Join(h.project, ".claude", "settings.json"):                      `{"permissions": {"allow": ["Bash(ls)"]}}` + "\n",
		filepath.Join(h.project, ".claude", "settings.local.json"):                "{}\n",
		filepath.Join(h.project, "notes.txt"):                                     "x\n",
		filepath.Join(h.home, ".codex", "config.toml"):                            gap0048CodexConfig,
		filepath.Join(h.home, ".config", "opencode", "plugins", "defenseclaw.js"): gap0048Bridge,
		filepath.Join(h.home, ".config", "opencode", "opencode.json"):             `{"plugin": ["file:///home/u/.defenseclaw/share/opencode/defenseclaw.js"], "model": "a"}` + "\n",
		filepath.Join(h.home, ".cursor", "hooks.json"):                            `{"version": 1, "hooks": {"beforeShellExecution": [{"command": "/home/u/.defenseclaw/hooks/cursor-hook.sh"}]}}` + "\n",
	}
	for name, body := range files {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(h.ext, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", h.home)
	t.Setenv("USERPROFILE", h.home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	return h
}

func (h gap0048Home) links(t *testing.T) bool {
	t.Helper()
	for link, target := range map[string]string{
		filepath.Join(h.ext, "proj-settings"): filepath.Join(h.project, ".claude", "settings.json"),
		filepath.Join(h.ext, "user-settings"): h.userSettings,
	} {
		if _, err := os.Lstat(link); err == nil {
			continue
		}
		if err := os.Symlink(target, link); err != nil {
			if runtime.GOOS == "windows" {
				return false
			}
			t.Fatal(err)
		}
	}
	return true
}

// gap0048Row is one tool call and its verdict in the default and the strict
// pack: block, alert or allow.
type gap0048Row struct {
	name, tool       string
	input            map[string]any
	defaults, strict string
	rule             string
	needsLinks       bool
}

func gap0048Judge(t *testing.T, connectorName, profile string, h gap0048Home, row gap0048Row) string {
	t.Helper()
	event := "PreToolUse"
	if connectorName == "opencode" {
		event = "tool.execute.before"
	}
	payload := mustJSON(t, map[string]any{"session_id": "gap0048", "hook_event_name": event,
		"tool_name": row.tool, "cwd": h.project, "tool_input": row.input})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	if profile == "strict" {
		installToolCallCorpusProfileConnector(t, connectorName, "strict")
		cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	}
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	if header := hookpaths.ResolveConnector(connectorName, "", event, payload); header != "" {
		req.Header.Set(hookpaths.Header, header)
	}
	if connectorName == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connectorName).ServeHTTP(recorder, req)
	return recorder.Body.String()
}

func gap0048Check(t *testing.T, connectorName string, h gap0048Home, rows []gap0048Row) {
	t.Helper()
	linked := h.links(t)
	for _, row := range rows {
		for _, profile := range []string{"default", "strict"} {
			want := row.defaults
			if profile == "strict" {
				want = row.strict
			}
			t.Run(row.name+"/"+profile, func(t *testing.T) {
				if row.needsLinks && !linked {
					t.Skip("no symlink privilege")
				}
				before := gap0048Snapshot(t, h)
				got := gap0048Judge(t, connectorName, profile, h, row)
				var answer struct {
					Action string `json:"action"`
				}
				if err := json.Unmarshal([]byte(got), &answer); err != nil {
					t.Fatalf("answer %q: %v", got, err)
				}
				if answer.Action != want {
					t.Fatalf("%s %s: action %q, want %q: %.700s", profile, row.name, answer.Action, want, got)
				}
				if want != "allow" && row.rule != "" && !strings.Contains(got, row.rule) {
					t.Fatalf("%s %s: want rule %s: %.700s", profile, row.name, row.rule, got)
				}
				if want == "allow" && (strings.Contains(got, agentHookConfigDisableRuleID) || strings.Contains(got, agentHookConfigWriteRuleID)) {
					t.Fatalf("%s %s: allowed call names a hook config rule: %.700s", profile, row.name, got)
				}
				if after := gap0048Snapshot(t, h); after != before {
					t.Fatal("the hook check changed a hook file")
				}
			})
		}
	}
}

func gap0048Snapshot(t *testing.T, h gap0048Home) string {
	t.Helper()
	var out strings.Builder
	for _, name := range []string{h.userSettings, filepath.Join(h.project, ".claude", "settings.json"),
		filepath.Join(h.home, ".codex", "config.toml"), filepath.Join(h.home, ".config", "opencode", "plugins", "defenseclaw.js")} {
		body, _ := os.ReadFile(name)
		out.Write(body)
	}
	return out.String()
}

// GAP-0048: on a per-user install an agent switched DefenseClaw off by
// writing its own hook config: disableAllHooks in a project
// .claude/settings.json silently, ~/.claude/settings.json with only an alert
// afterwards. A native Write, Edit or MultiEdit whose resulting document
// turns the hooks off is blocked in the default and strict packs, at the
// user, project and local levels and through a link; every other edit of
// these files is allowed; a shell write, whose content the gateway does not
// read, alerts in the default pack and blocks in strict.
func TestGAP0048ClaudeCodeHookConfigEdits(t *testing.T) {
	h := newGAP0048Home(t)
	user, project := h.userSettings, filepath.Join(h.project, ".claude", "settings.json")
	local := filepath.Join(h.project, ".claude", "settings.local.json")
	write := func(path, content string) map[string]any {
		return map[string]any{"file_path": path, "content": content}
	}
	edit := func(path, old, replacement string) map[string]any {
		return map[string]any{"file_path": path, "old_string": old, "new_string": replacement}
	}
	multi := func(path string, edits ...[2]string) map[string]any {
		items := make([]any, 0, len(edits))
		for _, e := range edits {
			items = append(items, map[string]any{"old_string": e[0], "new_string": e[1]})
		}
		return map[string]any{"file_path": path, "edits": items}
	}
	bash := func(command string) map[string]any { return map[string]any{"command": command} }
	disable := agentHookConfigDisableRuleID
	shell := agentHookConfigWriteRuleID
	gap0048Check(t, "claudecode", h, []gap0048Row{
		{name: "user Write disableAllHooks", tool: "Write", input: write(user, `{"disableAllHooks": true}`), defaults: "block", strict: "block", rule: disable},
		{name: "user Write wipe", tool: "Write", input: write(user, "{}"), defaults: "block", strict: "block", rule: disable},
		{name: "user Write keeps hooks and adds a permission", tool: "Write", input: write(user, strings.Replace(gap0048ClaudeUser, `"model": "sonnet",`, `"model": "sonnet", "permissions": {"allow": ["Bash(ls)"]},`, 1)), defaults: "allow", strict: "allow"},
		{name: "user Write unreadable", tool: "Write", input: write(user, `{"hooks": `), defaults: "block", strict: "block", rule: disable},
		{name: "user Edit adds disableAllHooks", tool: "Edit", input: edit(user, `"model": "sonnet",`, `"model": "sonnet", "disableAllHooks": true,`), defaults: "block", strict: "block", rule: disable},
		{name: "user Edit adds allowManagedHooksOnly", tool: "Edit", input: edit(user, `"model": "sonnet",`, `"model": "sonnet", "allowManagedHooksOnly": true,`), defaults: "block", strict: "block", rule: disable},
		{name: "user Edit rewrites the hook command", tool: "Edit", input: edit(user, "/home/u/.defenseclaw/bin/defenseclaw-hook-post", "/bin/true"), defaults: "block", strict: "block", rule: disable},
		{name: "user Edit changes the hook matcher", tool: "Edit", input: edit(user, `"matcher": "*"`, `"matcher": "NoSuchTool"`), defaults: "block", strict: "block", rule: disable},
		{name: "user Edit adds an env entry", tool: "Edit", input: edit(user, `"env": {"FOO": "1"}`, `"env": {"FOO": "1", "BAR": "2"}`), defaults: "allow", strict: "allow"},
		{name: "user Edit changes the model", tool: "Edit", input: edit(user, `"model": "sonnet"`, `"model": "opus"`), defaults: "allow", strict: "allow"},
		{name: "user Edit with an old text not in the file", tool: "Edit", input: edit(user, `"model": "haiku"`, `"model": "opus"`), defaults: "allow", strict: "allow"},
		{name: "user MultiEdit with one disabling edit", tool: "MultiEdit", input: multi(user, [2]string{`"model": "sonnet"`, `"model": "opus"`}, [2]string{`"env": {"FOO": "1"},`, `"env": {"FOO": "1"}, "disableAllHooks": true,`}), defaults: "block", strict: "block", rule: disable},
		{name: "user MultiEdit ordinary", tool: "MultiEdit", input: multi(user, [2]string{`"model": "sonnet"`, `"model": "opus"`}, [2]string{`"FOO": "1"`, `"FOO": "2"`}), defaults: "allow", strict: "allow"},
		{name: "project Write disableAllHooks", tool: "Write", input: write(project, `{"disableAllHooks": true}`), defaults: "block", strict: "block", rule: disable},
		{name: "project Write relative path", tool: "Write", input: write(".claude/settings.json", `{"permissions": {}, "disableAllHooks": true}`), defaults: "block", strict: "block", rule: disable},
		{name: "project Edit adds disableAllHooks", tool: "Edit", input: edit(project, `{"permissions"`, `{"disableAllHooks": true, "permissions"`), defaults: "block", strict: "block", rule: disable},
		{name: "project Edit adds a permission", tool: "Edit", input: edit(project, `"Bash(ls)"`, `"Bash(ls)", "Bash(git status)"`), defaults: "allow", strict: "allow"},
		{name: "project Write env and a hook of its own", tool: "Write", input: write(project, `{"env": {"X": "1"}, "hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "echo done"}]}]}}`), defaults: "allow", strict: "allow"},
		{name: "project Write disableAllHooks false", tool: "Write", input: write(project, `{"disableAllHooks": false}`), defaults: "allow", strict: "allow"},
		{name: "new nested project disableAllHooks", tool: "Write", input: write(filepath.Join(h.project, "sub", ".claude", "settings.json"), `{"disableAllHooks": true}`), defaults: "block", strict: "block", rule: disable},
		{name: "local Write disableAllHooks", tool: "Write", input: write(local, `{"disableAllHooks": true}`), defaults: "block", strict: "block", rule: disable},
		{name: "local Write env", tool: "Write", input: write(local, `{"env": {"X": "1"}}`), defaults: "allow", strict: "allow"},
		{name: "link to project settings disableAllHooks", tool: "Write", input: write(filepath.Join(h.ext, "proj-settings"), `{"disableAllHooks": true}`), defaults: "block", strict: "block", rule: disable, needsLinks: true},
		{name: "link to user settings wipe", tool: "Write", input: write(filepath.Join(h.ext, "user-settings"), "{}"), defaults: "block", strict: "block", rule: disable, needsLinks: true},
		{name: "link to project settings ordinary", tool: "Edit", input: edit(filepath.Join(h.ext, "proj-settings"), `"Bash(ls)"`, `"Bash(pwd)"`), defaults: "allow", strict: "allow", needsLinks: true},
		{name: "ordinary file named settings.json", tool: "Write", input: write(filepath.Join(h.project, "settings.json"), `{"disableAllHooks": true}`), defaults: "allow", strict: "allow"},
		{name: "Bash redirect into project settings", tool: "Bash", input: bash(`echo '{"disableAllHooks": true}' > .claude/settings.json`), defaults: "alert", strict: "block", rule: shell},
		{name: "Bash tee into user settings", tool: "Bash", input: bash(`echo '{}' | tee ~/.claude/settings.json`), defaults: "alert", strict: "block", rule: shell},
		{name: "Bash write through a link", tool: "Bash", input: bash(`echo '{}' > ` + filepath.ToSlash(filepath.Join(h.ext, "user-settings"))), defaults: "alert", strict: "block", rule: shell, needsLinks: true},
		{name: "user Write empties the file", tool: "Write", input: write(user, ""), defaults: "block", strict: "block", rule: disable},
		{name: "user Edit removes only the DefenseClaw SessionStart entry", tool: "Edit", input: edit(user, `,
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "/home/u/.defenseclaw/bin/defenseclaw-hook-user"}]}
    ]`, ""), defaults: "block", strict: "block", rule: disable},
		{name: "user Edit adds another hook beside DefenseClaw", tool: "Edit", input: edit(user, `"SessionStart": [`, `"Stop": [{"hooks": [{"type": "command", "command": "echo bye"}]}],
    "SessionStart": [`), defaults: "allow", strict: "allow"},
		{name: "local Write allowManagedHooksOnly", tool: "Write", input: write(local, `{"allowManagedHooksOnly": true}`), defaults: "block", strict: "block", rule: disable},
		{name: "Bash sed -i on user settings", tool: "Bash", input: bash(`sed -i 's/"hooks"/"x"/' ~/.claude/settings.json`), defaults: "alert", strict: "block", rule: shell},
		{name: "Bash cp over project settings", tool: "Bash", input: bash(`cp notes.txt .claude/settings.json`), defaults: "alert", strict: "block", rule: shell},
		{name: "Bash mv over user settings", tool: "Bash", input: bash(`mv notes.txt ~/.claude/settings.json`), defaults: "alert", strict: "block", rule: shell},
		{name: "Bash symlink swap of user settings", tool: "Bash", input: bash(`ln -sf /dev/null ~/.claude/settings.json`), defaults: "alert", strict: "block", rule: shell},
		{name: "Bash rm of user settings", tool: "Bash", input: bash(`rm -f ~/.claude/settings.json`), defaults: "alert", strict: "block", rule: shell},
		{name: "Bash truncate of local settings", tool: "Bash", input: bash(`: > .claude/settings.local.json`), defaults: "alert", strict: "block", rule: shell},
		{name: "Bash cp from settings to a backup", tool: "Bash", input: bash(`cp ~/.claude/settings.json notes.bak`), defaults: "allow", strict: "allow"},
		{name: "Bash read of settings", tool: "Bash", input: bash(`cat ~/.claude/settings.json .claude/settings.json`), defaults: "allow", strict: "allow"},
		{name: "Bash ordinary write", tool: "Bash", input: bash(`echo x >> notes.txt`), defaults: "allow", strict: "allow"},
	})
}

// The same guard for Codex (config.toml [features] hooks, its [hooks], an
// apply_patch envelope) and OpenCode (the bridge plugin and the plugin list).
func TestGAP0048CodexAndOpenCodeHookConfigEdits(t *testing.T) {
	h := newGAP0048Home(t)
	codexConfig := filepath.Join(h.home, ".codex", "config.toml")
	envelope := func(body string) map[string]any {
		return map[string]any{"command": "*** Begin Patch\n" + body + "*** End Patch"}
	}
	disable := agentHookConfigDisableRuleID
	t.Run("codex", func(t *testing.T) {
		gap0048Check(t, "codex", h, []gap0048Row{
			{name: "patch hooks false", tool: "apply_patch", input: envelope("*** Update File: " + codexConfig + "\n@@\n [features]\n-hooks = true\n+hooks = false\n"), defaults: "block", strict: "block", rule: disable},
			{name: "patch drops the hook command", tool: "apply_patch", input: envelope("*** Update File: " + codexConfig + "\n@@\n type = \"command\"\n-command = \"/home/u/.defenseclaw/hooks/codex-hook.sh\"\n+command = \"/bin/true\"\n"), defaults: "block", strict: "block", rule: disable},
			{name: "patch deletes config.toml", tool: "apply_patch", input: envelope("*** Delete File: " + codexConfig + "\n"), defaults: "block", strict: "block", rule: disable},
			{name: "shell sed -i hooks false", tool: "Bash", input: map[string]any{"command": `sed -i 's/hooks = true/hooks = false/' ~/.codex/config.toml`}, defaults: "alert", strict: "block", rule: agentHookConfigWriteRuleID},
			{name: "shell read of config", tool: "Bash", input: map[string]any{"command": `cat ~/.codex/config.toml`}, defaults: "allow", strict: "allow"},
			{name: "patch changes the model", tool: "apply_patch", input: envelope("*** Update File: " + codexConfig + "\n@@\n-model = \"gpt-5\"\n+model = \"gpt-5.5\"\n"), defaults: "allow", strict: "allow"},
		})
	})
	bridge := filepath.Join(h.home, ".config", "opencode", "plugins", "defenseclaw.js")
	openCodeConfig := filepath.Join(h.home, ".config", "opencode", "opencode.json")
	t.Run("opencode", func(t *testing.T) {
		gap0048Check(t, "opencode", h, []gap0048Row{
			{name: "write rewrites the bridge", tool: "write", input: map[string]any{"filePath": bridge, "content": "export const DefenseClaw = async () => ({})\n"}, defaults: "block", strict: "block", rule: disable},
			{name: "edit empties the bridge", tool: "edit", input: map[string]any{"filePath": bridge, "oldString": "export const DefenseClaw = async () => ({})", "newString": ""}, defaults: "block", strict: "block", rule: disable},
			{name: "plugin list without the bridge", tool: "write", input: map[string]any{"filePath": openCodeConfig, "content": `{"plugin": [], "model": "a"}`}, defaults: "block", strict: "block", rule: disable},
			{name: "shell rm of the bridge", tool: "bash", input: map[string]any{"command": `rm ~/.config/opencode/plugins/defenseclaw.js`}, defaults: "block", strict: "block", rule: agentHookConfigDisableRuleID},
			{name: "shell read of the bridge", tool: "bash", input: map[string]any{"command": `cat ~/.config/opencode/plugins/defenseclaw.js`}, defaults: "allow", strict: "allow"},
			{name: "plugin list keeps the bridge", tool: "edit", input: map[string]any{"filePath": openCodeConfig, "oldString": `"model": "a"`, "newString": `"model": "b"`}, defaults: "allow", strict: "allow"},
		})
	})
}

// agentHookConfigTurnsOff for each hook-file format the spec lists,
// including the Cursor, Devin and Copilot files.
func TestGAP0048HookConfigDocumentVerdicts(t *testing.T) {
	cursor := `{"version": 1, "hooks": {"beforeShellExecution": [{"command": "/h/.defenseclaw/hooks/cursor-hook.sh"}]}}`
	devin := "{\n  // Devin config\n  \"model\": \"x\",\n  \"hooks\": {\"pre_run_command\": [{\"command\": \"defenseclaw-hook devin\"}]},\n}"
	copilot := `{"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "/h/.defenseclaw/hooks/copilot-hook.sh"}]}}`
	for _, row := range []struct {
		name, format, before, after string
		afterExists, off            bool
	}{
		{"cursor wipe", gatewayconnector.AgentHookConfigJSONHooks, cursor, `{"version": 1, "hooks": {}}`, true, true},
		{"cursor another hook added", gatewayconnector.AgentHookConfigJSONHooks, cursor, `{"version": 1, "hooks": {"beforeShellExecution": [{"command": "/h/.defenseclaw/hooks/cursor-hook.sh"}, {"command": "lint"}]}}`, true, false},
		{"devin hooks removed", gatewayconnector.AgentHookConfigJSONHooks, devin, `{"model": "x"}`, true, true},
		{"devin model changed (JSONC)", gatewayconnector.AgentHookConfigJSONHooks, devin, strings.Replace(devin, `"x"`, `"y"`, 1), true, false},
		{"copilot hook file removed", gatewayconnector.AgentHookConfigJSONHooks, copilot, "", false, true},
		{"copilot settings disableAllHooks", gatewayconnector.AgentHookConfigCopilotSettings, `{"theme": "dark"}`, `{"theme": "dark", "disableAllHooks": true}`, true, true},
		{"copilot settings theme", gatewayconnector.AgentHookConfigCopilotSettings, `{"theme": "dark"}`, `{"theme": "light"}`, true, false},
		{"codex features codex_hooks false", gatewayconnector.AgentHookConfigCodexTOML, "[features]\nhooks = true\n", "[features]\nhooks = true\ncodex_hooks = false\n", true, true},
		{"codex already off stays off", gatewayconnector.AgentHookConfigCodexTOML, "[features]\nhooks = false\n", "model = \"y\"\n[features]\nhooks = false\n", true, false},
		{"claude already disabled", gatewayconnector.AgentHookConfigClaudeSettings, `{"disableAllHooks": true}`, `{"disableAllHooks": true, "model": "x"}`, true, false},
		{"claude non-boolean disableAllHooks", gatewayconnector.AgentHookConfigClaudeSettings, `{}`, `{"disableAllHooks": "yes"}`, true, true},
		{"claude project file removed", gatewayconnector.AgentHookConfigClaudeSettings, `{"disableAllHooks": false}`, "", false, false},
		{"bridge unchanged", gatewayconnector.AgentHookConfigBridge, gap0048Bridge, gap0048Bridge, true, false},
		{"bridge removed", gatewayconnector.AgentHookConfigBridge, gap0048Bridge, "", false, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			reason := agentHookConfigTurnsOff(row.format, []byte(row.before), true, []byte(row.after), row.afterExists)
			if (reason != "") != row.off {
				t.Fatalf("reason %q, want off=%v", reason, row.off)
			}
		})
	}
}
