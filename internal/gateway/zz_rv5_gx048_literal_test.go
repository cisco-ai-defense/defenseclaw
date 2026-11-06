package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRV5GX048LiteralRuns pins single-call, literal agent configuration changes
// across the two deployment modes and both shipped enforcement profiles.
func TestRV5GX048LiteralRuns(t *testing.T) {
	h := newGAP0048Home(t)
	off := filepath.Join(h.ext, "off.json")
	plain := filepath.Join(h.ext, "plain.json")
	for path, body := range map[string]string{
		off:   `{"disableAllHooks":true}`,
		plain: `{"theme":"dark","model":"sonnet"}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type row struct {
		name, command string
		block         bool
	}
	rows := []row{
		{"claude prefix dangerous", `CLAUDE_CONFIG_DIR=/tmp/x claude --dangerously-skip-permissions`, true},
		{"claude prefix prompt", `CLAUDE_CONFIG_DIR=/tmp/x claude -p hi`, true},
		{"claude prefix real home", `CLAUDE_CONFIG_DIR=` + filepath.Join(h.home, ".claude") + ` claude -p hi`, false},
		{"claude prefix real home tilde", `CLAUDE_CONFIG_DIR=~/.claude claude -p hi`, false},
		{"codex prefix exec", `CODEX_HOME=/tmp/x codex exec hi`, true},
		{"codex prefix real home", `CODEX_HOME=` + filepath.Join(h.home, ".codex") + ` codex exec hi`, false},
		{"codex prefix real home tilde", `CODEX_HOME=~/.codex codex exec hi`, false},
		{"claude inline off", `claude -p hi --settings '{"disableAllHooks":true}'`, true},
		{"claude inline theme", `claude -p hi --settings '{"theme":"dark"}'`, false},
		{"claude inline model", `claude -p hi --settings '{"model":"sonnet"}'`, false},
		{"claude readable off", `claude -p hi --settings ` + off, true},
		{"claude readable benign", `claude -p hi --settings ` + plain, false},
		{"npx claude inline off", `npx @anthropic-ai/claude-code --settings '{"disableAllHooks":true}'`, true},
		{"npx claude readable off", `npx @anthropic-ai/claude-code --settings ` + off, true},
		{"bunx claude inline off", `bunx @anthropic-ai/claude-code --settings '{"disableAllHooks":true}'`, true},
		{"pnpm dlx claude inline off", `pnpm dlx @anthropic-ai/claude-code --settings '{"disableAllHooks":true}'`, true},
		{"bunx claude version", `bunx @anthropic-ai/claude-code --version`, false},
		{"pnpm dlx claude version", `pnpm dlx @anthropic-ai/claude-code --version`, false},
		{"npx codex hooks off", `npx @openai/codex -c 'hooks={}' exec hi`, true},
		{"npx codex model", `npx @openai/codex -c 'model="gpt-5"' exec hi`, false},
		{"npx claude version", `npx claude-code --version`, false},
		{"env claude prefix", `env CLAUDE_CONFIG_DIR=/tmp/x claude -p hi`, true},
		{"env claude real home", `env CLAUDE_CONFIG_DIR=` + filepath.Join(h.home, ".claude") + ` claude -p hi`, false},
	}
	for _, r := range rows {
		for _, conn := range []string{"claudecode", "codex"} {
			for _, managed := range []bool{false, true} {
				for _, profile := range []string{"default", "strict"} {
					name := r.name + "/" + conn + "/" + profile
					if managed {
						name += "/managed"
					}
					t.Run(name, func(t *testing.T) {
						got := rv3Judge(t, conn, profile, h.project, managed, "Bash", map[string]any{"command": r.command})
						want := "allow"
						if r.block {
							want = "block"
						}
						if action := rv2Action(got); action != want {
							t.Errorf("%s: got %s, want %s: %s", r.command, action, want, strings.TrimSpace(got))
						}
					})
				}
			}
		}
	}
}
