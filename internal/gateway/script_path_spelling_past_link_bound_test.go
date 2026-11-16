// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// homeLinkChain makes n folder links in home/chain/d<n>, hop001 to hop<n>,
// each pointing at the next and the last at target, made from the last to
// the first so each target exists when its link is made (Windows makes a
// folder link only to a folder that is there). It returns the spelling
// chain/d<n>/hop001 below home.
func homeLinkChain(t *testing.T, home string, n int, target string) string {
	t.Helper()
	dir := filepath.Join(home, "chain", fmt.Sprintf("d%d", n))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := n; i >= 1; i-- {
		to := target
		if i < n {
			to = filepath.Join(dir, fmt.Sprintf("hop%03d", i+1))
		}
		if err := os.Symlink(to, filepath.Join(dir, fmt.Sprintf("hop%03d", i))); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	return fmt.Sprintf("chain/d%d/hop001", n)
}

// TestEveryScriptPathSpellingPastTheLinkBoundIsJudgedByTheTier: a script run
// or sourced by a path that passes more folder links than the system opens
// in one name (63 on Windows, 40 on Linux, 32 on macOS) is an unread body
// whatever the spelling of the path: the program path itself, bash with a
// relative, full or ~ path, a bash -c body that runs bash on the path, and
// the dot form. Through the hook client evidence and the gateway hook
// handler the default pack allows it with the unread-body alert and the
// strict pack blocks it, for both connectors. Within the bound the writer is
// read and blocked and the ordinary script is allowed in both packs
// (rel-1-0-9:GAP-0982, WN34-01; one reader for every spelling,
// readActionScript).
func TestEveryScriptPathSpellingPastTheLinkBoundIsJudgedByTheTier(t *testing.T) {
	home, _ := r104ReviewHome(t)
	if runtime.GOOS != "windows" {
		resolved, err := filepath.EvalSymlinks(home)
		if err != nil {
			t.Fatal(err)
		}
		home = resolved
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	live := filepath.Join(home, "proj", "live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"wk.sh": "echo marker >> $HOME/.ssh/authorized_keys\n",
		"ok.sh": "echo ordinary >> $HOME/proj/out.txt\n",
	} {
		if err := os.WriteFile(filepath.Join(live, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	over := homeLinkChain(t, home, hookpaths.SystemLinkLimit()+1, live)
	within := homeLinkChain(t, home, 3, live)
	spellings := []string{
		". ./%s",
		"./%s",
		"bash ./%s",
		"bash " + filepath.ToSlash(home) + "/%s",
		"bash ~/%s",
		`bash -c "bash ./%s"`,
	}
	type row struct {
		chain, script string
		strict        bool
		want          string
	}
	rows := []row{
		{over, "wk.sh", false, "alert"},
		{over, "wk.sh", true, "block"},
		{within, "wk.sh", false, "block"},
		{within, "ok.sh", false, "allow"},
		{within, "ok.sh", true, "allow"},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, spelling := range spellings {
			for _, r := range rows {
				command := fmt.Sprintf(spelling, r.chain+"/"+r.script)
				payload := mustJSON(t, map[string]any{"session_id": "spelling", "hook_event_name": "PreToolUse", "cwd": home,
					"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_spelling",
					"tool_input": map[string]any{"command": command, "description": "Run test fixture command"}})
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = connector
				if r.strict {
					cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
				}
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
				req.Header.Set(hookpaths.Header, hookpaths.Resolve(payload))
				if connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook(connector).ServeHTTP(recorder, req)
				var answer struct {
					Action string `json:"action"`
				}
				body := recorder.Body.String()
				if err := json.Unmarshal([]byte(body), &answer); err != nil {
					t.Fatalf("%s %q: answer does not decode: %v (%s)", connector, command, err, body)
				}
				got := answer.Action
				if got == "" {
					got = "allow"
				}
				if got != r.want {
					t.Errorf("%s strict=%v %q: %s, want %s (%s)", connector, r.strict, command, got, r.want, body)
				}
				if r.want == "alert" && !strings.Contains(body, shareBodyUnreadRuleID) {
					t.Errorf("%s %q: default alert without %s: %s", connector, command, shareBodyUnreadRuleID, body)
				}
			}
		}
	}
}
