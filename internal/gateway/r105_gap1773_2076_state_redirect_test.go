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
// GAP-2225: so is the redirect of a wrapped program.
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
		// GAP-2143 RV11-2: 1>&word, a quoted file word, another descriptor copy.
		{"aggregate redirect fd 1", "true 1>& ~/.defenseclaw/config.yaml", true},
		{"aggregate redirect fd 1 attached $HOME", "echo x 1>&$HOME/.defenseclaw/config.yaml", true},
		{"aggregate redirect quoted $HOME", `true >& "$HOME/.defenseclaw/config.yaml"`, true},
		{"aggregate redirect quoted ${HOME} hook", `echo x >& "${HOME}/.defenseclaw/hooks/claude-code-hook.sh"`, true},
		{"aggregate redirect after 2>&1", "ls 2>&1 >& ~/.defenseclaw/config.yaml", true},
		{"aggregate redirect before 2>&1", "ls >& ~/.defenseclaw/config.yaml 2>&1", true},
		{"descriptor duplicate fd 1", "echo x 1>&2", false},
		{"descriptor close", "exec 3>&-", false},
		{"descriptor variable", "echo x >&$fd", false},
		{"descriptor quoted variable", `echo x >&"$fd"`, false},
		{"aggregate redirect fd 1 build log", "make 1>& build.log", false},
		// GAP-2225: a home redirect target of a program with no operand grammar.
		{"make redirect", "make > ~/.defenseclaw/config.yaml", true},
		{"make append", "make >> ~/.defenseclaw/config.yaml", true},
		{"make target redirect", "make test > ~/.defenseclaw/config.yaml", true},
		{"make -C redirect", "make -C /tmp > ~/.defenseclaw/config.yaml", true},
		{"make hook redirect", "make > ~/.defenseclaw/hooks/claude-code-hook.sh", true},
		{"make $HOME redirect", "make > $HOME/.defenseclaw/config.yaml", true},
		{"npm redirect", "npm test > ~/.defenseclaw/config.yaml", true},
		{"go redirect", "go version > ~/.defenseclaw/config.yaml", true},
		{"python script redirect", "python3 build.py > ~/.defenseclaw/config.yaml", true},
		{"make aggregate redirect", "make &> ~/.defenseclaw/config.yaml", true},
		{"make build log", "make > build.log", false},
		{"make home project redirect", "make test > ~/proj/out.txt", false},
		{"npm $HOME project log", "npm test > $HOME/proj/test.log", false},
		{"go home file", "go version > ~/go-version.txt", false},
		{"make reads config", "make CONFIG=~/.defenseclaw/config.yaml > build.log", false},
		// GAP-2225 RV12-1: the same redirect behind an env, sudo or command wrapper.
		{"env make redirect", "env make > ~/.defenseclaw/config.yaml", true},
		{"env assignment make redirect", "env A=1 make > ~/.defenseclaw/config.yaml", true},
		{"sudo make redirect", "sudo make > ~/.defenseclaw/config.yaml", true},
		{"command make redirect", "command make > ~/.defenseclaw/config.yaml", true},
		{"env make $HOME hook", "env make > $HOME/.defenseclaw/hooks/claude-code-hook.sh", true},
		{"env make build log", "env make > ~/build.log", false},
		{"sudo make home log", "sudo make > ~/proj/build.log", false},
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
