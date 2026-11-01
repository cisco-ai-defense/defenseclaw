// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
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
		// Same-line staging through an abbreviated sort --output (pod check22).
		`cd ~ && printf 'PK' | sort --o=.defenseclaw.zip && yes | find ~ -maxdepth 1 -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} \;`,
		`cd ~ && printf 'PK' | sort -u --ou=.defenseclaw.zip && yes | find ~ -maxdepth 1 -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} + 2>&1 | head`,
		`cd ~ && printf 'PK' | sort --outp=.DefenseClaw.ZIP && yes | find ~ -maxdepth 1 -iname "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} \;`,
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
	// The rows of one fixture home share it (the staged rows add a
	// state-named archive): every per-user call first, with the home
	// readable, then every managed call, with the home unlistable and the
	// state tree unreadable. Each phase is answered concurrently by one
	// gateway per side, mode and connector, each call with a session of its
	// own, so the race build of the CI gateway shards stays within its
	// timing entry. Every row, mode and connector still runs.
	for _, staged := range []bool{false, true} {
		home, cwd := r105StateFixture(t)
		names := []string{"proj.zip", "a.orig"}
		if staged {
			names = append(names, ".defenseclaw.zip")
		}
		for _, name := range names {
			if err := os.WriteFile(filepath.Join(home, name), []byte("PK\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("HOME", home)
		var group []row
		var targets []map[string]string
		for _, r := range rows {
			if r.staged == staged {
				group = append(group, r)
				targets = append(targets, r105ClientTargets(t, r.command, cwd))
			}
		}
		var calls [2][]*findSinkCall
		for _, mode := range []string{"observe", "action"} {
			for _, connector := range []string{"claudecode", "codex"} {
				perUser, managed := findSinkGateway(t, connector, mode), findSinkGateway(t, connector, mode)
				for i, r := range group {
					call := func(api *APIServer, side string, targets map[string]string) *findSinkCall {
						payload := mustJSON(t, map[string]any{"session_id": fmt.Sprintf("findsink-%d", len(calls[0])+len(calls[1])),
							"hook_event_name": "PreToolUse", "cwd": cwd, "permission_mode": "default", "tool_name": "Bash",
							"tool_use_id": "toolu_r105", "tool_input": map[string]any{"command": r.command, "description": "Run test fixture command"}})
						return &findSinkCall{name: fmt.Sprintf("%s %s %s: %q", side, mode, connector, r.command), want: r.block,
							command: r.command, api: api, connector: connector, payload: payload, header: r105EncodeTargets(t, targets), managed: side == "managed"}
					}
					calls[0] = append(calls[0], call(perUser, "per-user", targets[i]))
					calls[1] = append(calls[1], call(managed, "managed", targets[i]))
					if !r.block {
						// An older client sends no state facts: a gateway that
						// cannot read the home still refuses.
						old := maps.Clone(targets[i])
						maps.DeleteFunc(old, func(key, _ string) bool {
							return strings.HasPrefix(key, hookpaths.StateRootSiblingsPrefix) ||
								strings.HasPrefix(key, hookpaths.StateTreeNamePrefix)
						})
						c := call(managed, "managed", old)
						c.oldClient = true
						calls[1] = append(calls[1], c)
					}
				}
			}
		}
		group0 := calls[0]
		eachConcurrently(len(group0), func(i int) { group0[i].answer(home) })
		// The managed gateway may not list the home or read the state tree.
		state := filepath.Join(home, ".defenseclaw")
		if err := os.Chmod(state, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(home, 0o311); err != nil {
			_ = os.Chmod(state, 0o700)
			t.Fatal(err)
		}
		if _, err := os.ReadDir(home); err == nil {
			_ = os.Chmod(home, 0o700)
			_ = os.Chmod(state, 0o700)
			t.Fatal("home still listable")
		}
		group1 := calls[1]
		eachConcurrently(len(group1), func(i int) { group1[i].answer(home) })
		_ = os.Chmod(home, 0o700)
		_ = os.Chmod(state, 0o700)
		for _, c := range append(group0, group1...) {
			switch {
			case c.oldClient:
				if !c.blocked && (strings.Contains(c.command, "%") || strings.Contains(c.command, "-delete") || strings.Contains(c.command, "rm -rf")) {
					t.Errorf("%s without the client facts allowed: %.300s", c.name, c.body)
				}
			case c.blocked != c.want:
				t.Errorf("%s blocked=%v, want %v: %.300s", c.name, c.blocked, c.want, c.body)
			}
		}
	}
}

// findSinkCall is one hook call of the GAP-2404 sink table and its answer.
type findSinkCall struct {
	name      string
	command   string
	want      bool
	oldClient bool
	api       *APIServer
	connector string
	payload   []byte
	header    string
	managed   bool
	blocked   bool
	body      string
}

// findSinkGateway is a hook gateway with the default pack in mode for
// connector (one per side, so a per-user call never answers for managed).
func findSinkGateway(t *testing.T, connector, mode string) *APIServer {
	t.Helper()
	api := instructionProtectionTestAPI(t, connector, mode, "")
	api.health = NewSidecarHealth()
	return api
}

// answer posts the call with the hook client's target header, as the
// verified managed hook peer of home when managed; the caller sets the
// home and state tree modes of the phase.
func (c *findSinkCall) answer(home string) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(c.payload)))
	req.Header.Set(hookpaths.Header, c.header)
	if c.connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if c.managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	recorder := httptest.NewRecorder()
	c.api.handleAgentHook(c.connector).ServeHTTP(recorder, req)
	c.body = recorder.Body.String()
	c.blocked = strings.HasPrefix(c.body, `{"action":"block"`)
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
		"sort --o=out": false, "sort --outp=out": false, "sort -u --ou=out": false,
		"sort --compress=sh": false, "sort --temporary=d": false, "sort --files0=list": false,
		"grep --fil=pats x": false, "grep --regexp x file": false, "wc --files0=list": false,
		"sort --numeric-sort --reverse": true, "sort --key=2 --unique": true, "sort --key 2": true,
		"head --lines=5": true, "tail --lines 1": true, "wc --lines": true, "uniq --count": true,
		"grep --regexp=x --ignore-case": true, "grep --regexp x": true, "cat --number": true,
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
