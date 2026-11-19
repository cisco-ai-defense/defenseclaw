// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// listPrefixHookPost sends command as the tool call tool of connector's hook route
// and returns the action and the rule IDs of the answer.
func listPrefixHookPost(t *testing.T, a *APIServer, connector, tool, command string, managedPeer bool) (string, string) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0348", "cwd": `C:\work`,
		"tool_name": tool, "tool_use_id": "tu-gap0348", "tool_input": map[string]any{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(connector, "", "PreToolUse", raw))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if managedPeer {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: `C:\Users\alice`}))
	}
	w := httptest.NewRecorder()
	a.handleAgentHook(connector).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s %s: status %d: %s", connector, tool, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: answer %q: %v", connector, w.Body.String(), err)
	}
	action, _ := out["action"].(string)
	return action, w.Body.String()
}

// listPrefixFindingRules are the rule IDs of a hook answer's findings.
func listPrefixFindingRules(t *testing.T, raw string) []string {
	t.Helper()
	var out struct {
		Findings []string `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	rules := make([]string, 0, len(out.Findings))
	for _, finding := range out.Findings {
		rule, _, _ := strings.Cut(finding, ":")
		rules = append(rules, rule)
	}
	return rules
}

// listPrefixActionRank orders hook actions by strength.
func listPrefixActionRank(action string) int {
	switch action {
	case "block", "deny":
		return 2
	case "alert", "warn", "ask":
		return 1
	}
	return 0
}

// TestGAP0348TrailingStatementKeepsTheVerdictFiveTiers pins
// rel-1-0-10:GAP-0348. On a Windows hook the dialect selection places
// `<attack> ; echo done` in no dialect: its POSIX reading is complete but
// places no .git/config under a Windows folder, and its PowerShell reading is
// partial with no readable-statements reading, so a trailing benign statement
// hid the git read writing .git/config (and the fork bomb on Claude Code's
// Git Bash tool). The list without its last statement is read as the hook
// reads that call (windowsListPrefixTwinRequest): the wrapped call gets the
// verdict of the attack alone, in the five tiers, on the Codex shell and
// Claude Code's Bash tool. Benign lists a developer runs keep their verdict
// (no new block or alert in default).
func TestGAP0348TrailingStatementKeepsTheVerdictFiveTiers(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	type row struct{ connector, tool, attack, wrapped string }
	attacks := []row{
		{"codex", "Bash", "git show --output=.git/config HEAD", "git show --output=.git/config HEAD ; echo done"},
		{"codex", "Bash", "git show --output=.git/config HEAD", "git show --output=.git/config HEAD\necho done"},
		{"codex", "Bash", "git show --output=.git/config HEAD", "git show --output=.git/config HEAD && echo ok"},
		{"codex", "Bash", "git -C project show --output=.git/config HEAD", "git -C project show --output=.git/config HEAD ; echo done"},
		{"codex", "Bash", ":(){ :|:& };:", ":(){ :|:& };: ; echo done"},
		// A Bash call Git Bash reads alone is placed in POSIX on a Windows
		// host (hookpaths.GitBashReadsAlone) and keeps the POSIX reading, as
		// on Linux and macOS (rel-1-0-10:GAP-1561); a PowerShell spelling in
		// the trailer keeps the call in no dialect.
		{"claudecode", "Bash", ":(){ :|:& };:", ":(){ :|:& };: ; Write-Output done"},
	}
	benign := []string{
		"git status; echo done",
		"git log -1 ; echo done",
		"make build && make test",
		"cd x && ls; pwd",
		"npm test || echo failed",
		"git diff --stat HEAD; git status",
	}
	for _, p := range gap0437Packs {
		for _, connector := range []string{"codex", "claudecode"} {
			a := gap0437Server(t, p, connector, "action")
			for _, r := range attacks {
				if r.connector != connector {
					continue
				}
				bare, bareRaw := listPrefixHookPost(t, a, connector, r.tool, r.attack, p.managed)
				bareRules := listPrefixFindingRules(t, bareRaw)
				if len(bareRules) == 0 {
					t.Fatalf("%s %s %q: the attack alone is %q with no finding, the row proves nothing: %.300s", p.name, connector, r.attack, bare, bareRaw)
				}
				wrapped, raw := listPrefixHookPost(t, a, connector, r.tool, r.wrapped, p.managed)
				wrappedRules := listPrefixFindingRules(t, raw)
				if listPrefixActionRank(wrapped) < listPrefixActionRank(bare) {
					t.Errorf("%s %s %q: %q, want %q as alone: %.400s", p.name, connector, r.wrapped, wrapped, bare, raw)
				}
				for _, rule := range bareRules {
					if !slices.Contains(wrappedRules, rule) {
						t.Errorf("%s %s %q: no %s finding, which the attack alone has: %.400s", p.name, connector, r.wrapped, rule, raw)
					}
				}
			}
			if p.name != "default" && p.name != "permissive" {
				continue
			}
			for _, command := range benign {
				if action, raw := listPrefixHookPost(t, a, connector, "Bash", command, p.managed); listPrefixActionRank(action) != 0 ||
					len(listPrefixFindingRules(t, raw)) != 0 {
					t.Errorf("%s %s benign %q: %q: %.400s", p.name, connector, command, action, raw)
				}
			}
		}
	}
}

// TestGAP0348ListPrefixReadingBound: the list-prefix reading is one reading
// of a Windows hook call placed in no dialect whose POSIX list has two or more
// statements; never a reading twin's, a single statement's, a call placed in
// a dialect, or a Linux or macOS hook call (no Windows readings).
func TestGAP0348ListPrefixReadingBound(t *testing.T) {
	for _, c := range []struct{ command, prefix string }{
		{"a ; b", "a"},
		{"a\nb", "a"},
		{"a && b", "a"},
		{"a || b", "a"},
		{"a; b && c", "a; b"},
		{"a && b; c", "a && b"},
		{"a && b && c", "a && b"},
		{":(){ :|:& };: ; echo done", ":(){ :|:& };:"},
		{"a & b", "a &"},
		{"a", ""},
		{"a | b", ""},
		{"! a && b", "! a"},
		{"! (a && b)", ""},
		{"(a; b)", ""},
		{"{ a; b; }", ""},
		{"if a; then b; fi", ""},
		{"a 'b", ""},
	} {
		got, ok := posixListPrefix(c.command)
		if got != c.prefix || ok != (c.prefix != "") {
			t.Errorf("posixListPrefix(%q) = %q, %v; want %q", c.command, got, ok, c.prefix)
		}
	}
	args, err := json.Marshal(map[string]string{"command": "git show --output=.git/config HEAD ; echo done"})
	if err != nil {
		t.Fatal(err)
	}
	call := trustedActionRequest{Input: actionfacts.Input{Tool: "Bash", Args: args, CWD: `C:\work`}}
	facts := actionfacts.Analyze(call.Input)
	if _, ok := windowsListPrefixTwinRequest(call, facts); ok {
		t.Error("a call with no Windows readings (a Linux or macOS hook) has a list-prefix reading")
	}
	withWindowsShellDialect(&call, true)
	twin, ok := windowsListPrefixTwinRequest(call, actionfacts.Analyze(call.Input))
	if !ok || twin.Input.Command != "git show --output=.git/config HEAD" || !twin.readingTwin ||
		twin.Input.DialectHint != actionfacts.DialectPowerShell {
		t.Fatalf("Windows hook call: twin %v %q hint %q", ok, twin.Input.Command, twin.Input.DialectHint)
	}
	if _, again := windowsListPrefixTwinRequest(twin, actionfacts.Analyze(twin.Input)); again {
		t.Error("a reading twin makes a list-prefix reading of its own")
	}
	placed := call
	placed.Input.DialectHint = actionfacts.DialectPOSIX
	if _, ok := windowsListPrefixTwinRequest(placed, actionfacts.Analyze(placed.Input)); ok {
		t.Error("a call placed in a dialect has a list-prefix reading")
	}
}
