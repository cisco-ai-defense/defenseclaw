// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// tdCodexVerdict is the verdict of command through the Codex hook handler in
// cwd, with the folder evidence the Codex hook client sends.
func tdCodexVerdict(t *testing.T, a *APIServer, session, cwd, command string) string {
	t.Helper()
	body := string(mustJSON(t, map[string]any{"session_id": session, "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "cwd": cwd, "tool_input": map[string]any{"command": command}}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(body)))
	setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	rec := httptest.NewRecorder()
	a.handleAgentHook("codex").ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	action, _ := out["action"].(string)
	if action == "" {
		action = "allow"
	}
	return map[string]string{"allow": "A", "alert": "L", "block": "B"}[action]
}

// TestUnresolvedFolderCurrentFolderSpellingOnEveryRoute is
// rel-1-0-10:GAP-1042, the residual of GAP-1023 (cells of the s7-td327r3rev3
// probe TestRV3Probe, built from the operands and heads of
// TestUnresolvedFolderCurrentFolderSpellingIsThePlainOne*). After a cd to a
// folder the call does not give, a current-folder head before a protected
// operand gets at least the verdict of the plain spelling of the same form
// in each of the 5 packs: on the Codex hook (its client sends the folder the
// call starts in, which does not place a statement after the cd), inside a
// nested bash -c body (the body starts in that unknown folder), and in a
// variable assigned from the head after the cd (its value is the operand in
// that folder); a nested body of a call with no folder from the agent is
// read so too. The plain verdict is the oracle, read at run time; the
// rows below pin that it is the tier.
func TestUnresolvedFolderCurrentFolderSpellingOnEveryRoute(t *testing.T) {
	_, project := cdFirstFixture(t)
	dot := "."
	// A key file and a key pattern: the AWS file and the other operands of
	// the GAP-1023 tables take the same reading (TestRV3Probe), and the
	// matrix stays within one CI shard under -race.
	operands := []string{dot + "ssh/id_rsa", dot + "ssh/id_*"}
	forms := []string{"cat %s", `bash -c "cat %s"`, `X=%s; cat "$X"`, `export X=%s; cp "$X" /tmp/staged`}
	type route struct {
		name    string
		verdict func(t *testing.T, a *APIServer, session, cwd, command string) string
	}
	routes := []route{
		{"claudecode", func(t *testing.T, a *APIServer, session, cwd, command string) string {
			got, _ := tdCurrentFolderVerdict(t, a, session, cwd, command)
			return got
		}},
		{"codex", tdCodexVerdict},
	}
	for _, r := range routes {
		for _, p := range gap0437Packs {
			a := gap0437Server(t, p, r.name, "action")
			tier := "L"
			if strings.Contains(p.name, "strict") {
				tier = "B"
			}
			session := "td-route-" + r.name + "-" + p.name
			judged := 0
			for _, cd := range []string{"cd \"$TD327_UNSET\" && ", "cd -- \"$(mktemp -d)\" && ", ""} {
				cwd := project
				if cd == "" {
					cwd = "" // no folder from the agent: the nested body
				}
				for _, form := range forms {
					if cwd == "" && (r.name != "claudecode" || !strings.HasPrefix(form, "bash -c")) {
						continue
					}
					for _, operand := range operands {
						plain := tdOrUnknown(r.verdict(t, a, session, cwd, cd+strings.Replace(form, "%s", operand, 1)))
						if operand == dot+"ssh/id_rsa" && cdFirstRank[plain] < cdFirstRank[tier] {
							t.Errorf("%s %s: the plain %q is %s, want at least %s", r.name, p.name,
								cd+strings.Replace(form, "%s", operand, 1), plain, tier)
						}
						for _, head := range tdCurrentFolderHeads() {
							if strings.HasPrefix(form, "bash -c") && strings.Contains(head, `"`) {
								continue // a quote of its own would end the body
							}
							spelled := cd + strings.Replace(form, "%s", head+"/"+operand, 1)
							judged++
							if got := tdOrUnknown(r.verdict(t, a, session, cwd, spelled)); cdFirstRank[got] < cdFirstRank[plain] {
								t.Errorf("%s %s: %q is %s, the plain spelling is %s", r.name, p.name, spelled, got, plain)
							}
						}
					}
				}
			}
			if judged == 0 {
				t.Fatalf("%s %s: no cell judged", r.name, p.name)
			}
		}
	}
}

// tdOrUnknown is a verdict letter, "?" for an answer with no action.
func tdOrUnknown(verdict string) string {
	if verdict == "" {
		return "?"
	}
	return verdict
}
