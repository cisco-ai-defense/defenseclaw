// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAgentHookConfigNestedAgentLaunches pins that a nested agent run that
// points the agent at another config home, strips the home, or turns its
// hooks off inline or through a readable settings file is blocked however the
// run is spelled (prefix assignment, quoted word, wrapper, package runner,
// nested shell), while a run that names the real home, an ordinary setting or
// only a model stays allowed.
func TestAgentHookConfigNestedAgentLaunches(t *testing.T) {
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
	realClaude := filepath.Join(h.home, ".claude")
	off1 := `--settings '{"disableAllHooks":true}'`
	rows := []hookConfigShellRow{
		{"config home elsewhere", `CLAUDE_CONFIG_DIR=/tmp/x claude -p hi`, "block"},
		{"quoted prefix word", `"CLAUDE_CONFIG_DIR=/tmp/x" claude -p hi`, "block"},
		{"codex home elsewhere", `CODEX_HOME=/tmp/x npx -y @openai/codex exec hi`, "block"},
		{"home stripped by env", `env -u HOME claude -p hi`, "block"},
		{"home stripped by an abbreviated env option", `env --uns=HOME claude -p hi`, "block"},
		{"environment cleared by env", `env --ignore-environment claude -p hi`, "block"},
		{"home replaced inside a nested shell", `HOME=/tmp/x bash -lc 'claude -p hi'`, "block"},
		{"inline settings that disable the hooks", `claude -p hi ` + off1, "block"},
		{"readable settings file that disables the hooks", `claude -p hi --settings ` + off, "block"},
		{"inline disable through npx", `npx @anthropic-ai/claude-code ` + off1, "block"},
		{"inline disable through npm exec", `npm exec -- @anthropic-ai/claude-code -p hi ` + off1, "block"},
		{"inline disable through a package option", `npx --package=@anthropic-ai/claude-code claude -p hi ` + off1, "block"},
		{"inline disable behind a process wrapper", `timeout -k 5 60 claude ` + off1 + ` -p hi`, "block"},
		{"inline disable in a nested shell", `sh -ec 'claude --settings '\''{"disableAllHooks":true}'\'' -p hi'`, "block"},
		{"inline disable behind stdbuf", `stdbuf -oL claude ` + off1 + ` -p hi`, "block"},
		{"inline disable in a nested shell with quotes", `bash -lc "claude -p hi --settings '{\"disableAllHooks\":true}'"`, "block"},
		{"codex hooks table emptied", `npx @openai/codex -c 'hooks={}' exec hi`, "block"},
		{"codex feature table off", `codex -c 'features={hooks=false}' exec hi`, "block"},
		{"codex feature flag off behind timeout", `timeout --signal=KILL 60s codex -c features.hooks=false exec hi`, "block"},
		{"config home elsewhere behind an abbreviated env option", `env --ch /tmp claude ` + off1 + ` -p hi`, "block"},
		{"the real config home", `CLAUDE_CONFIG_DIR=` + filepath.ToSlash(realClaude) + ` claude -p hi`, "allow"},
		{"the real config home by tilde", `CLAUDE_CONFIG_DIR=~/.claude claude -p hi`, "allow"},
		{"the home kept", `HOME=$HOME claude -p hi`, "allow"},
		{"the home unset then set again", `env --uns=HOME HOME=` + filepath.ToSlash(h.home) + ` claude -p hi`, "allow"},
		{"another name unset", `env --uns LC_ALL claude -p hi`, "allow"},
		{"inline ordinary setting", `claude -p hi --settings '{"theme":"dark"}'`, "allow"},
		{"readable ordinary settings file", `claude -p hi --settings ` + filepath.ToSlash(plain), "allow"},
		{"inline ordinary setting in a nested shell", `bash -lc 'claude --settings '\''{"model":"opus"}'\'' -p hi'`, "allow"},
		{"codex feature table on", `codex -c 'features={hooks=true}' exec hi`, "allow"},
		{"codex model override", `npx @openai/codex -c 'model="gpt-5"' exec hi`, "allow"},
		{"claude version through bunx", `bunx @anthropic-ai/claude-code --version`, "allow"},
		{"claude behind a process wrapper", `timeout -k 5 60 claude -p hi`, "allow"},
		{"git status in a nested shell", `dash -ec 'git status'`, "allow"},
	}
	checkHookConfigShellRows(t, h, rows)
}
