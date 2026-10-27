// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-1773: a write redirect to $HOME/, ${HOME}/ or "$HOME/..." active state
// got no path fact, so the state owner never saw it. GAP-2076: neither did
// the redirect of the ":" builtin or of a command-less redirect (`> f`).
// All of them are writes of the redirect target, as `true > f` already was.
func TestR105StateRedirectSpellingsAreWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command matrix")
	}
	home, cwd := r104ReviewHome(t)
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(hooks, "claude-code-hook.sh")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name, command string
		block         bool
	}{
		{"$HOME config", "printf x >> $HOME/.defenseclaw/config.yaml", true},
		{"${HOME} config", "printf x >> ${HOME}/.defenseclaw/config.yaml", true},
		{"quoted $HOME config", `printf x >> "$HOME/.defenseclaw/config.yaml"`, true},
		{"$HOME overwrite hook", "echo x > $HOME/.defenseclaw/hooks/claude-code-hook.sh", true},
		{"partly quoted $HOME config", `printf x >"$HOME"/.defenseclaw/config.yaml`, true},
		{"partly quoted $HOME colon", `: >"$HOME"/.defenseclaw/config.yaml`, true},
		{"partly quoted ${HOME} config", `printf x > "${HOME}"/.defenseclaw/config.yaml`, true},
		{"quoted $HOME then single-quoted suffix", `printf x > "$HOME"'/.defenseclaw/config.yaml'`, true},
		{"partly quoted $HOME hook", `echo x > "$HOME"/.defenseclaw/hooks/claude-code-hook.sh`, true},
		{"partly quoted $HOME rm argument", `rm -f "$HOME"/.defenseclaw/config.yaml`, true},
		{"quoted $HOME rm argument", `rm -f "$HOME/.defenseclaw/config.yaml"`, true},
		{"aggregate redirect", "true &> ~/.defenseclaw/config.yaml", true},
		{"aggregate append redirect", "echo x &>> ~/.defenseclaw/config.yaml", true},
		{"aggregate redirect duplicate form", "true >& ~/.defenseclaw/config.yaml", true},
		{"aggregate redirect $HOME hook", "echo x &> $HOME/.defenseclaw/hooks/claude-code-hook.sh", true},
		{"colon aggregate redirect", ": &> ~/.defenseclaw/config.yaml", true},
		{"bare aggregate redirect", "&> ~/.defenseclaw/config.yaml", true},
		{"aggregate redirect absolute", "true &> " + home + "/.defenseclaw/config.yaml", true},
		{"aggregate redirect duplicate form absolute", "true >& " + home + "/.defenseclaw/config.yaml", true},
		{"partly quoted $HOME project write", `printf x > "$HOME"/proj/notes.txt`, false},
		{"partly quoted $HOME read", `cat "$HOME"/.defenseclaw/config.yaml`, false},
		{"aggregate redirect build log", "make &> build.log", false},
		{"aggregate redirect null", "true &> /dev/null", false},
		{"descriptor duplicate", "echo x >&2", false},
		{"colon truncate", ": > ~/.defenseclaw/config.yaml", true},
		{"colon append", ": >> ~/.defenseclaw/config.yaml", true},
		{"bare truncate", "> ~/.defenseclaw/config.yaml", true},
		{"colon hook", ": > ~/.defenseclaw/hooks/claude-code-hook.sh", true},
		{"colon $HOME", ": > $HOME/.defenseclaw/config.yaml", true},
		{"colon notes", ": > notes.txt", false},
		{"bare build log", "> build.log", false},
		{"read $HOME config", "cat $HOME/.defenseclaw/config.yaml", false},
		{"mention $HOME path", `printf '%s\n' "$HOME/.defenseclaw/config.yaml" > notes.txt`, false},
		{"$HOMEX look-alike", "printf x >> $HOMEX/.defenseclaw/config.yaml", false},
		{"$HOME project write", "printf x >> $HOME/proj/notes.txt", false},
		// GAP-1773 RV11-1: a double-quoted literal part after the "$HOME" part.
		{"quoted $HOME then double-quoted name", `printf x > "$HOME"/.defenseclaw/"config.yaml"`, true},
		{"quoted $HOME then double-quoted name rm", `rm -f "$HOME"/.defenseclaw/"config.yaml"`, true},
		{"quoted $HOME then double-quoted project name", `printf x > "$HOME"/proj/"notes.txt"`, false},
		{"quoted $HOME then double-quoted name read", `cat "$HOME"/.defenseclaw/"config.yaml"`, false},
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, tc := range tests {
			t.Run(connectorName+"/"+tc.name, func(t *testing.T) {
				input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: cwd, ActiveHome: home,
					DialectHint: actionfacts.DialectPOSIX}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, Connector: connectorName, EnforcementCapable: true,
				})
				if got := buildVerdict(findings, "tool_call").Action == guardrailActionBlock; got != tc.block {
					t.Fatalf("block=%t, want %t; findings=%v", got, tc.block, FindingStrings(findings))
				}
				if tc.block && findingWithID(findings, "tamper.detector_state_write") == nil {
					t.Fatalf("no tamper.detector_state_write finding; findings=%v", FindingStrings(findings))
				}
			})
		}
	}
}
