// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

type homeStateWriteRow struct {
	command string
	block   bool
}

func judgeHomeStateWriteRows(t *testing.T, rows []homeStateWriteRow) {
	t.Helper()
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(cwd, "a.txt"),
	} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
			for _, row := range rows {
				command := strings.ReplaceAll(row.command, "HOMEDIR", home)
				input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home, DialectHint: hint}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, Connector: connectorName, EnforcementCapable: true,
				})
				blocked := buildVerdict(findings, "tool_call").Action == "block"
				if blocked != row.block {
					t.Errorf("%s hint=%q %q: block=%v, want %v", connectorName, hint, row.command, blocked, row.block)
				}
			}
		}
	}
}

// One runtime-expanded operand word made the argv of cp, mv and install
// partial, and the partial call tied no path to itself, so a literal or
// home-spelled destination in DefenseClaw state went unjudged: an extra
// $(true), `true`, `# note` or $EMPTY after it, or a dynamic source before
// it, let the write through with no finding (GAP-2477).
func TestDynamicOperandWordKeepsTheStateWriteJudged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"cp a.txt $HOME/.defenseclaw/config.yaml $(true)", true},
		{"cp a.txt $HOME/.defenseclaw/config.yaml `true`", true},
		{"cp a.txt HOMEDIR/.defenseclaw/config.yaml `true`", true},
		{"cp a.txt HOMEDIR/.defenseclaw/config.yaml `# note`", true},
		{"cp a.txt ~/.defenseclaw/config.yaml $(true) $(true)", true},
		{"cp a.txt HOMEDIR/.defenseclaw/config.yaml $EMPTY", true},
		{"cp $(echo a.txt) HOMEDIR/.defenseclaw/config.yaml", true},
		{"cp $SRC ~/.defenseclaw/config.yaml", true},
		{"cp a.txt $(true) HOMEDIR/.defenseclaw/config.yaml", true},
		{"mv a.txt $HOME/.defenseclaw/hooks/pc8-f.sh $(true)", true},
		{"install a.txt HOMEDIR/.defenseclaw/hooks/pc8-f.sh $(true)", true},
		{"cp a.txt ~/.ssh/authorized_keys $(true)", true},
		{"cp a.txt HOMEDIR/.defenseclaw/config.yaml", true},
		// The benign twins stay allowed: a project copy with a command
		// substitution, a read of state into a runtime directory, and a
		// quoted substitution, which is always one more word.
		{"cp a.txt out.txt $(true)", false},
		{"cp a.txt ~/project/out.txt $(date +%s)", false},
		{"cp $(ls *.txt) ~/project/", false},
		{"cp HOMEDIR/.defenseclaw/config.yaml backup.yaml $(true)", false},
		{"cp ~/.defenseclaw/config.yaml $(mktemp -d)/", false},
		{"cp a.txt HOMEDIR/.defenseclaw/config.yaml \"$(true)\"", false},
		{"mv $(ls *.log) archive/", false},
	})
}

// export HOME=v reads like HOME=v; export HOME: a later ~ or $HOME write
// names v, so a write that then lands in DefenseClaw state blocks
// (GAP-2476). An export of HOME to an ordinary directory stays allowed.
func TestExportHomeAssignmentMovesTheHomeSpelling(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"export HOME=$HOME/.defenseclaw; cp a.txt ~/config.yaml", true},
		{"export HOME=$HOME/.defenseclaw; cp a.txt $HOME/config.yaml", true},
		{"export HOME=HOMEDIR/.defenseclaw; cp a.txt ~/config.yaml", true},
		{"export HOME=HOMEDIR/.defenseclaw\ncp a.txt ~/config.yaml", true},
		{"declare -x HOME=HOMEDIR/.defenseclaw; cp a.txt ~/config.yaml", true},
		{"readonly HOME=HOMEDIR/.defenseclaw; cp a.txt ~/config.yaml", true},
		{"HOME=HOMEDIR/.defenseclaw; export HOME; cp a.txt ~/config.yaml", true},
		{"export HOME=HOMEDIR/.ssh; echo k >> ~/authorized_keys", true},
		{"export HOME=/tmp/pc11x; cp a.txt ~/config.yaml", false},
		{"export HOME=HOMEDIR/project; cp a.txt ~/out.txt", false},
		{"export PATH=$PATH:/opt/bin; cp a.txt ~/project/out.txt", false},
	})
}

// Behind ProtectHome (a managed hook peer) the readings of GAP-2477 add no
// unknown target of their own: a benign project copy with a runtime word
// stays allowed, and a keys-file destination still blocks.
func TestDynamicOperandWordManagedHookPeer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home := t.TempDir()
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "payload")} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{"cp payload out.txt $(true)", false},
		{"cp $SRC out.txt", false},
		{"mv payload done/ $(true)", false},
		{"cp payload ~/.ssh/authorized_keys $(true)", true},
	} {
		t.Run(tc.command, func(t *testing.T) {
			body := string(mustJSON(t, map[string]any{"session_id": "gap2477", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": tc.command}}))
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "codex"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(body))
			req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(body)))
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			recorder := httptest.NewRecorder()
			api.handleAgentHook("codex").ServeHTTP(recorder, req)
			got := recorder.Body.String()
			if blocked := strings.HasPrefix(got, `{"action":"block"`); blocked != tc.block {
				t.Fatalf("blocked = %t, want %t: %.600s", blocked, tc.block, got)
			}
		})
	}
}
