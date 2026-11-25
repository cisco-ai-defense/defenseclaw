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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestGAP1090ManagedRelativeShellProfileWriteMatchesPerUser is
// substrate-1:GAP-1090 (live on dc-ent-rhel, 1.0.10 and the fold): a
// managed gateway sits behind ProtectHome and receives no cwd of its own,
// so `echo x >> .bashrc` from the home was not placed on ~/.bashrc and was
// a clean allow, where a per-user gateway alerts (strict blocks)
// persistence.shell_profile_write; ~/.bashrc, the absolute path and
// `cd ~ && echo x >> .bashrc` alerted on both. The managed reading must be
// at least the per-user one for every relative spelling, and for the
// GAP-0690 function row that the relative form hid on managed, and the
// function rows with an unresolved command in the body (substrate-1:GAP-1091).
// The controls stay allowed on both: a write of another file
// in the home, a read of .bashrc, and a project's own .bashrc, which is not
// the user's profile.
func TestGAP1090ManagedRelativeShellProfileWriteMatchesPerUser(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	for _, name := range []string{filepath.Join(f.home, ".bashrc"), filepath.Join(f.home, ".profile"), filepath.Join(f.project, ".bashrc"), filepath.Join(f.home, "notes.txt")} {
		if err := os.WriteFile(name, []byte("# fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type row struct {
		id, where, command string
		// profile: the per-user reading flags it (the fixture premise).
		profile bool
	}
	rows := []row{
		{"R1", "h", "echo x >> .bashrc", true},
		{"R2", "h", "echo x >> ./.bashrc", true},
		{"R3", "h", "echo x >> ~/.bashrc", true},
		{"R4", "h", "cd ~ && echo x >> .bashrc", true},
		{"R5", "p", "echo x >> ../.bashrc", true},
		{"R6", "h", "printf x > .profile", true},
		{"R7", "h", "tee -a .bashrc < /dev/null", true},
		{"F0690", "h", "f(){ test -f .bashrc && return; cd /tmp; }; f && echo x >> .bashrc", false},
		// The same with an unresolved command in the body (GAP-0693 $r,
		// GAP-0694 "$@", GAP-0711 eval and $y): per-user, the unknown tier of
		// the unread part puts the call under the cap floor, whose piece
		// `echo x >> .bashrc` is judged alone in the home. The managed reading
		// in the client's directory must run that floor too
		// (substrate-1:GAP-1091). The ~/.bashrc forms below already matched.
		{"F0693", "h", "f(){ cd /tmp; $r ~; }; f && echo x >> .bashrc", true},
		{"F0694", "h", "f(){ cd /tmp; \"$@\"; }; f cd && echo x >> .bashrc", true},
		{"F0711a", "h", "f(){ cd /tmp; eval \"$c\"; }; f && echo x >> .bashrc", true},
		{"F0711b", "h", "f(){ $y; }; f && echo x >> .bashrc", true},
		{"T0693", "h", "f(){ cd /tmp; $r ~; }; f && echo x >> ~/.bashrc", false},
		{"T0711b", "h", "f(){ $y; }; f && echo x >> ~/.bashrc", false},
		{"N1", "h", "echo x >> notes.txt", false},
		{"N2", "h", "cat .bashrc", false},
		{"N3", "p", "echo x >> .bashrc", false},
		{"N4", "h", "echo x >> project/notes.txt", false},
		// GAP-1091 controls: the same call on an ordinary file, and on a
		// project's own profile-named file, stays allowed on both.
		{"N5", "h", "f(){ $y; }; f && echo x >> notes.txt", false},
		{"N6", "p", "f(){ $y; }; f && echo x >> .bashrc", false},
	}
	benign := func(r row) bool { return strings.HasPrefix(r.id, "N") }
	payloads := make([][]byte, 0, 2*len(rows))
	for _, r := range rows {
		cwd := f.project
		if r.where == "h" {
			cwd = f.home
		}
		for _, side := range []string{"peruser", "managed"} {
			payloads = append(payloads, mustJSON(t, map[string]any{"session_id": "g1090-" + r.id + "-" + side,
				"hook_event_name": "PreToolUse", "cwd": cwd, "permission_mode": "default", "tool_name": "Bash",
				"tool_use_id": "toolu_g1090", "tool_input": map[string]any{"command": r.command, "description": "Run test fixture command"}}))
		}
	}
	headers := f.clientHeaders(t, payloads)
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	type answer struct{ verdict, rules string }
	ask := func(api *APIServer, payload []byte, header string, managed bool) answer {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
		req.Header.Set(hookpaths.Header, header)
		if managed {
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
		}
		recorder := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
		var response agentHookResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			return answer{verdict: fmt.Sprintf("status %d body %.300s", recorder.Code, recorder.Body.String())}
		}
		verdict := response.RawAction
		if verdict == "" {
			verdict = response.Action
		}
		if verdict == "warn" {
			verdict = "alert"
		}
		return answer{verdict: verdict, rules: strings.Join(response.RuleIDs, ",")}
	}
	defer os.Chmod(f.homes, 0o700)
	for _, pack := range []string{"default", "strict"} {
		for _, mode := range []string{"action", "observe"} {
			api := keyReadGateway(t, "claudecode", pack, mode)
			perUser := make([]answer, len(rows))
			managed := make([]answer, len(rows))
			if err := os.Chmod(f.homes, 0o700); err != nil {
				t.Fatal(err)
			}
			for i := range rows {
				perUser[i] = ask(api, payloads[2*i], headers[2*i], false)
			}
			if err := os.Chmod(f.homes, 0); err != nil {
				t.Fatal(err)
			}
			for i := range rows {
				managed[i] = ask(api, payloads[2*i+1], headers[2*i+1], true)
			}
			if err := os.Chmod(f.homes, 0o700); err != nil {
				t.Fatal(err)
			}
			for i, r := range rows {
				name := fmt.Sprintf("%s %s/%s %q", r.id, pack, mode, r.command)
				p, m := perUser[i], managed[i]
				if _, ok := rank[m.verdict]; !ok {
					t.Errorf("%s: managed answer %s", name, m.verdict)
					continue
				}
				switch {
				case benign(r):
					if p.verdict != "allow" || m.verdict != "allow" {
						t.Errorf("%s: per-user %s (%s), managed %s (%s), want allow on both", name, p.verdict, p.rules, m.verdict, m.rules)
					}
				case r.profile && !strings.Contains(p.rules, "persistence.shell_profile_write"):
					t.Errorf("%s: per-user %s (%s), want persistence.shell_profile_write (fixture premise)", name, p.verdict, p.rules)
				case rank[m.verdict] < rank[p.verdict]:
					t.Errorf("%s: managed %s (%s), per-user %s (%s)", name, m.verdict, m.rules, p.verdict, p.rules)
				case r.profile && !strings.Contains(m.rules, "persistence.shell_profile_write"):
					t.Errorf("%s: managed %s (%s), want persistence.shell_profile_write as per-user", name, m.verdict, m.rules)
				}
			}
		}
	}
}
