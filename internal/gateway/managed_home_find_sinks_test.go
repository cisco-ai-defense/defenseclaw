// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-2404 pod check21 (P1): two benign-block classes of a home find on a
// managed gateway, which cannot read the user's home or state tree.
//  1. A read-only pipe sink after the find (`... _ {} + 2>&1 | head`,
//     `| tail -1`, `| wc -l`) refused the "${1%.zip}" strip line check, on
//     managed and per-user hosts.
//  2. A find that deletes by a name no state file has (`find ~ -name
//     '.DS_Store' -delete`, node_modules -prune -exec rm -rf) was judged by
//     the semantic owner with the gateway's own state-tree index, which a
//     managed gateway cannot read, so every name counted as state; the hook
//     client's StateTreeNameKey answers were ignored there.
//
// Attack rows (a state-named archive with a sink, state-named deletes) and
// an older client map without the facts still block.
func TestR105GAP2404HomeFindSinksAndNameDeletesOnManaged(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX shell forms; needs a home the process cannot list")
	}
	benign := []string{
		`find ~ -name '*.orig' -delete`,
		`find ~ -name '.DS_Store' -delete`,
		`find ~ -type d -name node_modules -prune -exec rm -rf {} +`,
		`find ~ -name '*.orig' -delete | wc -l`,
		`find ~ -name '*.orig' -delete; echo ok`,
		`find ~ -name '*.orig' -print -delete`,
		`find ~ -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} + | tail -1`,
		`find ~ -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} + 2>&1 | head`,
		`find ~ -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} + | grep -v warning | sort | uniq -c`,
	}
	attack := []string{
		`find ~ -name config.yaml -delete`,
		`find ~ -name hooks -exec rm -rf {} +`,
		`find ~ -name policies -prune -exec rm -rf {} +`,
		`find ~ -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} + | tee ~/out.txt`,
		`find ~ -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} + | sort -o ~/.defenseclaw.zip`,
		`find ~ -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} + | sh`,
	}
	stagedAttack := []string{
		`find ~ -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} + 2>&1 | head`,
		`find ~ -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} + | tail -1`,
	}
	type row struct {
		command string
		block   bool
		staged  bool
	}
	var rows []row
	for _, command := range benign {
		rows = append(rows, row{command: command})
	}
	for _, command := range attack {
		rows = append(rows, row{command: command, block: true})
	}
	for _, command := range stagedAttack {
		rows = append(rows, row{command: command, block: true, staged: true})
	}
	for _, r := range rows {
		home, cwd := r105StateFixture(t)
		for _, name := range []string{"proj.zip", "a.orig"} {
			if err := os.WriteFile(filepath.Join(home, name), []byte("PK\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if r.staged {
			if err := os.WriteFile(filepath.Join(home, ".defenseclaw.zip"), []byte("PK\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("HOME", home)
		targets := r105ClientTargets(t, r.command, cwd)
		for _, mode := range []string{"observe", "action"} {
			for _, connector := range []string{"claudecode", "codex"} {
				if blocked, body := r105PerUserHook(t, connector, mode, r.command, cwd, targets); blocked != r.block {
					t.Errorf("per-user %s %s: %q blocked=%v, want %v: %.300s", mode, connector, r.command, blocked, r.block, body)
				}
				blocked, body := r105ManagedHook(t, connector, mode, r.command, cwd, home, targets)
				if blocked != r.block {
					t.Errorf("managed %s %s: %q blocked=%v, want %v: %.300s", mode, connector, r.command, blocked, r.block, body)
				}
				if !r.block {
					// An older client sends no state facts: a gateway that
					// cannot read the home still refuses.
					old := maps.Clone(targets)
					maps.DeleteFunc(old, func(key, _ string) bool {
						return strings.HasPrefix(key, hookpaths.StateRootSiblingsPrefix) ||
							strings.HasPrefix(key, hookpaths.StateTreeNamePrefix)
					})
					if blocked, body := r105ManagedHook(t, connector, mode, r.command, cwd, home, old); !blocked &&
						(strings.Contains(r.command, "%") || strings.Contains(r.command, "-delete") || strings.Contains(r.command, "rm -rf")) {
						t.Errorf("managed %s %s: %q without the client facts allowed: %.300s", mode, connector, r.command, body)
					}
				}
			}
		}
	}
}

// The stdin filter rule is narrow: options and one grep pattern only.
func TestR105GAP2404FindStripStdinFilterStaysOff(t *testing.T) {
	for command, want := range map[string]bool{
		"head": true, "head -n 5": true, "tail -1": true, "wc -l": true, "sort -u": true,
		"uniq -c": true, "grep -v warning": true, "grep -e x -i": true, "cat": true, "sort -k2 -n": true,
		"head a.txt": false, "tail -n 1 ~/x": false, "sort -o out": false, "sort -uo out": false,
		"sort --output=out": false, "sort -T dir": false, "grep -f pats": false, "grep x file": false,
		"uniq in out": false, "cat file": false, "tee out": false, "xargs rm": false, "sh": false,
		"wc --files0-from=list": false, "env head": false,
	} {
		facts := r105AnalyzeBash(t, command)
		got := len(facts.Commands) != 0
		for _, fact := range facts.Commands {
			got = got && findStripStdinFilterStaysOff(facts, fact)
		}
		if got != want {
			t.Errorf("%q: stays off = %v, want %v", command, got, want)
		}
	}
}

func r105AnalyzeBash(t *testing.T, command string) actionfacts.Facts {
	t.Helper()
	return actionfacts.Analyze(actionfacts.Input{
		Tool: "Bash", Args: mustJSON(t, map[string]any{"command": command}),
		CWD: "/tmp", ActiveHome: "/home/alice",
	})
}

// r105PerUserHook posts command as a per-user hook call (the gateway may
// read the home) with the hook client's target map.
func r105PerUserHook(t *testing.T, connector, mode, command, cwd string, targets map[string]string) (bool, string) {
	t.Helper()
	payload := mustJSON(t, map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": cwd,
		"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_r105",
		"tool_input": map[string]any{"command": command, "description": "Run test fixture command"}})
	api := instructionProtectionTestAPI(t, connector, mode, "")
	api.health = NewSidecarHealth()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	req.Header.Set(hookpaths.Header, r105EncodeTargets(t, targets))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	got := recorder.Body.String()
	return strings.HasPrefix(got, `{"action":"block"`), got
}
