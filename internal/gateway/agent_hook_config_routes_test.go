// Regression rows from the independent near-variant review.

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
)

func TestGAP0048Round2RegistryAndDocuments(t *testing.T) {
	h := newGAP0048Home(t)
	guard := newAgentHookConfigGuard(h.project, h.home)
	for _, row := range []struct{ name, path, format string }{
		{"Amp", filepath.Join(h.home, ".config", "amp", "plugins", "defenseclaw.ts"), gatewayconnector.AgentHookConfigBridge},
		{"Antigravity", filepath.Join(h.home, ".gemini", "config", "hooks.json"), gatewayconnector.AgentHookConfigJSONHooks},
		{"Kiro hooks", filepath.Join(h.home, ".kiro", "hooks", "defenseclaw.json"), gatewayconnector.AgentHookConfigJSONHooks},
		{"Kiro agent", filepath.Join(h.home, ".kiro", "agents", "kiro_default.json"), gatewayconnector.AgentHookConfigJSONHooks},
		{"Kiro settings", filepath.Join(h.home, ".kiro", "settings", "cli.json"), gatewayconnector.AgentHookConfigKiroSettings},
		{"Hermes", hermespath.ConfigPathForUserHome(h.home), gatewayconnector.AgentHookConfigHermesYAML},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := guard.format(row.path); got != row.format {
				t.Fatalf("format %q, want %q", got, row.format)
			}
		})
	}
	for _, row := range []struct{ name, format, before, after string }{
		{"Amp bridge", gatewayconnector.AgentHookConfigBridge, "// DefenseClaw", ""},
		{"Antigravity hooks", gatewayconnector.AgentHookConfigJSONHooks, `{"hooks":{"pre":[{"command":"defenseclaw-hook"}]}}`, `{}`},
		{"Kiro hooks", gatewayconnector.AgentHookConfigJSONHooks, `{"hooks":{"pre":[{"command":"defenseclaw-hook"}]}}`, `{}`},
		{"Kiro default", gatewayconnector.AgentHookConfigKiroSettings, `{"chat.defaultAgent":"kiro_default"}`, `{"chat.defaultAgent":"other"}`},
		{"Hermes YAML", gatewayconnector.AgentHookConfigHermesYAML, "hooks:\n  pre_tool_call:\n    - command: defenseclaw-hook\n", "hooks: {}\n"},
	} {
		t.Run(row.name, func(t *testing.T) {
			if reason := agentHookConfigTurnsOff(row.format, []byte(row.before), true, []byte(row.after), true); reason == "" {
				t.Fatal("registration removal was allowed")
			}
		})
	}
}

func TestGAP0048Round2Variants(t *testing.T) {
	h := newGAP0048Home(t)
	if err := os.MkdirAll(filepath.Join(h.project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.project, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.links(t)
	user := h.userSettings
	project := filepath.Join(h.project, ".claude", "settings.json")
	codexConfig := filepath.Join(h.home, ".codex", "config.toml")
	ampPlugin := filepath.Join(h.home, ".config", "amp", "plugins", "defenseclaw.ts")
	antigravityHooks := filepath.Join(h.home, ".gemini", "config", "hooks.json")
	kiroHooks := filepath.Join(h.home, ".kiro", "hooks", "defenseclaw.json")
	kiroAgent := filepath.Join(h.home, ".kiro", "agents", "kiro_default.json")
	kiroSettings := filepath.Join(h.home, ".kiro", "settings", "cli.json")
	hermesConfig := hermespath.ConfigPathForUserHome(h.home)
	for path, body := range map[string]string{
		ampPlugin:                              "// DefenseClaw Amp plugin\n",
		antigravityHooks:                       `{"hooks":{"pre":[{"command":"defenseclaw-hook"}]}}`,
		kiroHooks:                              `{"hooks":{"pre":[{"command":"defenseclaw-hook"}]}}`,
		kiroAgent:                              `{"hooks":{"pre":[{"command":"defenseclaw-hook"}]}}`,
		kiroSettings:                           `{"chat.defaultAgent":"kiro_default"}`,
		hermesConfig:                           "hooks:\n  pre_tool_call:\n    - command: defenseclaw-hook\n",
		filepath.Join(h.project, "safe.patch"): "--- a/notes.txt\n+++ b/notes.txt\n@@ -1 +1 @@\n-x\n+y\n",
		filepath.Join(h.project, "hook.patch"): "--- a/.claude/settings.json\n+++ b/.claude/settings.json\n@@ -1 +1 @@\n-{}\n+{}\n",
		filepath.Join(h.project, "unknown.patch"): "diff --git \"a/.claude/settings.json\" \"b/.claude/settings.json\"\nGIT binary patch\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src := filepath.Join(h.ext, "cfg")
	_ = os.MkdirAll(src, 0o700)
	_ = os.WriteFile(filepath.Join(src, "settings.json"), []byte("{}\n"), 0o600)
	_ = os.Symlink(filepath.Join(h.home, ".claude"), filepath.Join(h.ext, "cdir"))
	hard := filepath.Join(h.project, "copy-of-user.json")
	_ = os.Link(user, hard)
	projectHard := filepath.Join(h.project, "copy-of-project.json")
	_ = os.Link(project, projectHard)
	S := filepath.ToSlash
	w := func(p, c string) map[string]any { return map[string]any{"file_path": p, "content": c} }
	e := func(p, o, n string) map[string]any {
		return map[string]any{"file_path": p, "old_string": o, "new_string": n}
	}
	b := func(c string) map[string]any { return map[string]any{"command": c} }
	patch := func(body string) map[string]any {
		return map[string]any{"command": "*** Begin Patch\n" + body + "*** End Patch"}
	}
	type row struct {
		id, conn, tool, want string
		in                   map[string]any
	}
	rows := []row{
		// protected, shell model (want: alert default, block strict)
		{"S01 cp named source into the folder", "claudecode", "Bash", "shell", b("cp " + S(filepath.Join(src, "settings.json")) + " .claude/")},
		{"S02 cp folder contents, trailing slash", "claudecode", "Bash", "benign", b("cp -r " + S(src) + "/ ~/.claude/")},
		{"S03 rename the user folder", "claudecode", "Bash", "shell", b("mv ~/.claude ~/.claude-old")},
		{"S04 remove the user folder", "claudecode", "Bash", "shell", b("rm -rf ~/.claude")},
		{"S05 install onto the file", "claudecode", "Bash", "shell", b("install -m 600 notes.txt ~/.claude/settings.json")},
		{"S06 rsync onto the file", "claudecode", "Bash", "shell", b("rsync notes.txt ~/.claude/settings.json")},
		{"S07 interpreter write naming the file", "claudecode", "Bash", "shell", b(`python3 -c "open('.claude/settings.json','w').write('{}')"`)},
		{"S08 node write naming the file", "claudecode", "Bash", "shell", b(`node -e "require('fs').writeFileSync('.claude/settings.json','{}')"`)},
		{"S09 git restore of project settings", "claudecode", "Bash", "shell", b("git restore --source=HEAD~1 .claude/settings.json")},
		{"S10 git checkout of project settings", "claudecode", "Bash", "shell", b("git checkout HEAD~1 -- .claude/settings.json")},
		{"S10a git stash pop in project", "claudecode", "Bash", "shell", b("git stash pop")},
		{"S10b git reset hard in project", "claudecode", "Bash", "shell", b("git reset --hard HEAD~1")},
		{"S10c git apply in project", "claudecode", "Bash", "shell", b("git apply change.patch")},
		{"S10d git apply registration patch", "claudecode", "Bash", "shell", b("git apply hook.patch")},
		{"S10e git apply unknown patch section", "claudecode", "Bash", "shell", b("git apply unknown.patch")},
		{"S10f git apply multiple patches", "claudecode", "Bash", "shell", b("git apply safe.patch hook.patch")},
		{"S11 redirect via $HOME spelling", "claudecode", "Bash", "shell", b(`echo '{}' > "$HOME/.claude/settings.json"`)},
		{"S12 redirect via absolute spelling", "claudecode", "Bash", "shell", b("echo '{}' > " + S(user))},
		{"S13 folder link swap", "claudecode", "Bash", "benign", b("ln -sfn " + S(src) + " ~/.claude")},
		{"S14 rename the codex folder", "codex", "Bash", "shell", b("mv ~/.codex ~/.codex-old")},
		{"S15 remove the opencode plugins folder", "opencode", "bash", "native", b("rm -rf ~/.config/opencode/plugins")},
		{"S16 nested agent run with inline settings", "claudecode", "Bash", "native", b(`claude -p hi --settings '{"disableAllHooks": true}'`)},
		{"S16a nested agent through env", "claudecode", "Bash", "native", b(`env FOO=bar claude -p hi --settings '{"disableAllHooks": true}'`)},
		{"S16b nested Copilot settings", "claudecode", "Bash", "native", b(`copilot --settings '{"disableAllHooks": true}'`)},
		{"S17 nested Codex feature override", "codex", "Bash", "native", b("codex -c features.hooks=false exec hi")},
		{"S18 nested OpenCode plugin override", "claudecode", "Bash", "native", b(`opencode --config '{"plugin":[]}'`)},
		// protected, post-edit model (want: block in both)
		{"N01 Write through a linked folder", "claudecode", "Write", "native", w(filepath.Join(h.ext, "cdir", "settings.json"), "{}")},
		{"N02 Write with dot segments", "claudecode", "Write", "native", w(filepath.Join(h.project, "..", ".claude", ".", "settings.json"), "{}")},
		{"N03 Write via tilde", "claudecode", "Write", "native", w("~/.claude/settings.json", "{}")},
		{"N04 Write through a second name of the same file", "claudecode", "Write", "native", w(hard, "{}")},
		{"N04 project file identity", "claudecode", "Write", "native", w(projectHard, `{"disableAllHooks": true}`)},
		{"N04a protected hook runtime env", "claudecode", "Edit", "native", e(user, `"FOO": "1"`, `"FOO": "1", "DEFENSECLAW_HOME": "/tmp/other"`)},
		{"N04b protected loader env", "claudecode", "Edit", "native", e(user, `"FOO": "1"`, `"FOO": "1", "LD_PRELOAD": "/tmp/other.so"`)},
		{"N04c Amp plugin rewrite", "claudecode", "Write", "native", w(ampPlugin, "// changed\n")},
		{"N04d Antigravity hook removal", "claudecode", "Write", "native", w(antigravityHooks, "{}")},
		{"N04e Kiro hook removal", "claudecode", "Write", "native", w(kiroHooks, "{}")},
		{"N04f Kiro agent hook removal", "claudecode", "Write", "native", w(kiroAgent, "{}")},
		{"N04g Kiro default agent change", "claudecode", "Write", "native", w(kiroSettings, `{"chat.defaultAgent":"other"}`)},
		{"N04h Hermes hook removal", "claudecode", "Write", "native", w(hermesConfig, "hooks: {}\n")},
		{"N05 local settings in nested project", "claudecode", "Write", "native", w(filepath.Join(h.project, "a", "b", ".claude", "settings.local.json"), `{"disableAllHooks": true}`)},
		{"N06 Edit replace_all of the hook path", "claudecode", "Edit", "native", map[string]any{"file_path": user, "old_string": "/home/u/.defenseclaw", "new_string": "/tmp/x", "replace_all": true}},
		{"N07 codex patch moves config away", "codex", "apply_patch", "native", patch("*** Update File: " + codexConfig + "\n*** Move to: " + filepath.Join(h.home, "old.toml") + "\n@@\n-model = \"gpt-5\"\n+model = \"gpt-5\"\n")},
		{"N08 codex dotted features key", "codex", "apply_patch", "benign", patch("*** Update File: " + codexConfig + "\n@@\n-[features]\n-hooks = true\n+[features]\n+hooks = true\n+\n+[x]\n")},
		{"N09 codex inline features off", "codex", "apply_patch", "native", patch("*** Update File: " + codexConfig + "\n@@\n-[features]\n-hooks = true\n+features = { hooks = false }\n")},
		{"N10 NotebookEdit on settings", "claudecode", "NotebookEdit", "benign", map[string]any{"notebook_path": user, "new_source": "{}", "edit_mode": "replace"}},
		// benign (want: allow in both)
		{"B01 permission add", "claudecode", "Edit", "benign", e(project, `"Bash(ls)"`, `"Bash(ls)", "Bash(npm test)"`)},
		{"B02 env value change", "claudecode", "Edit", "benign", e(user, `"FOO": "1"`, `"FOO": "2"`)},
		{"B03 model change", "claudecode", "Edit", "benign", e(user, `"model": "sonnet"`, `"model": "haiku"`)},
		{"B04 statusLine add", "claudecode", "Edit", "benign", e(user, `"model": "sonnet",`, `"model": "sonnet", "statusLine": {"type": "command", "command": "echo hi"},`)},
		{"B05 add a PostToolUse hook", "claudecode", "Edit", "benign", e(user, `"SessionStart": [`, `"PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "npx prettier --write ."}]}], "SessionStart": [`)},
		{"B06 cleanupPeriodDays", "claudecode", "Edit", "benign", e(user, `"model": "sonnet",`, `"model": "sonnet", "cleanupPeriodDays": 30,`)},
		{"B07 project settings rewrite keeps no DC", "claudecode", "Write", "benign", w(project, `{"permissions": {"deny": ["Read(.env)"]}, "env": {"NODE_ENV": "test"}}`)},
		{"B08 new local settings", "claudecode", "Write", "benign", w(filepath.Join(h.project, ".claude", "settings.local.json"), `{"permissions": {"allow": ["Bash(make)"]}}`)},
		{"B09 user Write same hooks new model", "claudecode", "Write", "benign", w(user, `{"model": "opus", "env": {"FOO": "1"}, "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "/home/u/.defenseclaw/bin/defenseclaw-hook-post", "timeout": 30}]}], "SessionStart": [{"hooks": [{"type": "command", "command": "/home/u/.defenseclaw/bin/defenseclaw-hook-user"}]}]}}`)},
		{"B10 codex model change", "codex", "apply_patch", "benign", patch("*** Update File: " + codexConfig + "\n@@\n-model = \"gpt-5\"\n+model = \"o4\"\n")},
		{"B11 codex add mcp server", "codex", "apply_patch", "benign", patch("*** Update File: " + codexConfig + "\n@@\n model = \"gpt-5\"\n+\n+[mcp_servers.docs]\n+command = \"docs-mcp\"\n")},
		{"B12 opencode theme", "opencode", "edit", "benign", map[string]any{"filePath": filepath.Join(h.home, ".config", "opencode", "opencode.json"), "oldString": `"model": "a"`, "newString": `"model": "a", "theme": "dark"`}},
		{"B13 shell cat", "claudecode", "Bash", "benign", b("cat ~/.claude/settings.json")},
		{"B14 shell jq read", "claudecode", "Bash", "benign", b("jq '.permissions' .claude/settings.json")},
		{"B15 shell jq to stdout", "claudecode", "Bash", "benign", b("jq . ~/.codex/config.toml 2>/dev/null; grep -n hooks ~/.claude/settings.json")},
		{"B16 shell diff", "claudecode", "Bash", "benign", b("diff ~/.claude/settings.json .claude/settings.json")},
		{"B17 shell git diff", "claudecode", "Bash", "benign", b("git diff -- .claude/settings.json")},
		{"B18 shell backup copy out", "claudecode", "Bash", "benign", b("cp .claude/settings.json /tmp/settings.backup.json")},
		{"B19 shell ls folder", "claudecode", "Bash", "benign", b("ls -la ~/.claude/ .claude/")},
		{"B20 interpreter read", "claudecode", "Bash", "benign", b(`python3 -c "import json;print(json.load(open('.claude/settings.json')))"`)},
		{"B21 Write ordinary json elsewhere", "claudecode", "Write", "benign", w(filepath.Join(h.project, "config", "settings.json"), `{"disableAllHooks": true}`)},
		{"B22 Read tool of settings", "claudecode", "Read", "benign", map[string]any{"file_path": user}},
		{"B23 git apply check", "claudecode", "Bash", "benign", b("git apply --check change.patch")},
		{"B24 git index-only restore", "claudecode", "Bash", "benign", b("git restore --staged .claude/settings.json")},
		{"B25 nested agent benign settings", "claudecode", "Bash", "benign", b(`claude -p hi --settings '{"model":"sonnet","env":{"FOO":"2"}}'`)},
		{"B26 nested Codex benign override", "codex", "Bash", "benign", b("codex -c model=fast exec hi")},
		{"B27 git apply unrelated patch", "claudecode", "Bash", "benign", b("git apply safe.patch")},
		{"B28 nested OpenCode model override", "claudecode", "Bash", "benign", b(`opencode --config '{"model":"fast"}'`)},
	}
	for _, profile := range []string{"default", "strict"} {
		t.Run(profile, func(t *testing.T) {
			judges := map[string]hookConfigJudge{}
			for _, r := range rows {
				if judges[r.conn] == nil {
					judges[r.conn] = newHookConfigJudge(t, r.conn, profile)
				}
			}
			for _, r := range rows {
				t.Run(r.id, func(t *testing.T) {
					t.Parallel()
					got := hookConfigAction(judges[r.conn](h.project, false, r.tool, r.in))
					want := "allow"
					switch {
					case r.want == "native":
						want = "block"
					case r.want == "shell" && profile == "default":
						want = "alert"
					case r.want == "shell":
						want = "block"
					}
					if got != want {
						t.Errorf("got %s, want %s", got, want)
					}
				})
			}
		})
	}
}
