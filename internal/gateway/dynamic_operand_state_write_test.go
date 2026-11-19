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

// homeStateRuleRow is a row that blocks in the default pack for rules of its
// own (not as the HIGH state write alert): the block and each named rule id
// are the oracle (gap0747BlockedForRule, GAP-1563).
type homeStateRuleRow struct {
	command string
	rules   []string
}

func judgeHomeStateWriteRows(t *testing.T, rows []homeStateWriteRow) {
	t.Helper()
	judgeHomeStateRows(t, rows, nil)
}

func judgeHomeStateRuleRows(t *testing.T, rows []homeStateRuleRow) {
	t.Helper()
	judgeHomeStateRows(t, nil, rows)
}

func judgeHomeStateRows(t *testing.T, rows []homeStateWriteRow, ruleRows []homeStateRuleRow) {
	t.Helper()
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"), filepath.Join(home, ".local", "bin"), cwd} {
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
				// row.block: a proven state write, a HIGH alert in the default
				// tier (GAP-0747); other blocking rules keep blocking.
				if msg := gap0747DefaultTierCheck(findings, row.block); msg != "" {
					t.Errorf("%s hint=%q %q: %s (want %v) %v", connectorName, hint, row.command, msg, row.block, FindingStrings(findings))
				}
			}
			for _, row := range ruleRows {
				command := strings.ReplaceAll(row.command, "HOMEDIR", home)
				input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home, DialectHint: hint}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, Connector: connectorName, EnforcementCapable: true,
				})
				if msg := gap0747BlockedForRule(findings, row.rules...); msg != "" {
					t.Errorf("%s hint=%q %q: %s %v", connectorName, hint, row.command, msg, FindingStrings(findings))
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
	// These rows block in the default pack for rules of their own, not as
	// the HIGH state write alert (GAP-1563).
	judgeHomeStateRuleRows(t, []homeStateRuleRow{
		{"cp a.txt ~/.ssh/authorized_keys $(true)", []string{gap0747SSHKeysRule}},
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
		{"export HOME=/tmp/pc11x; cp a.txt ~/config.yaml", false},
		{"export HOME=HOMEDIR/project; cp a.txt ~/out.txt", false},
		{"export PATH=$PATH:/opt/bin; cp a.txt ~/project/out.txt", false},
	})
	// These rows block in the default pack for rules of their own, not as
	// the HIGH state write alert (GAP-1563).
	judgeHomeStateRuleRows(t, []homeStateRuleRow{
		{"export HOME=HOMEDIR/.ssh; echo k >> ~/authorized_keys", []string{gap0747SSHKeysRule}},
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
