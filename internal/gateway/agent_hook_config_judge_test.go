// Shared judge for the agent hook config regression tests.

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// hookConfigJudge judges one tool call through the agent hook handler built by
// newHookConfigJudge.
type hookConfigJudge func(cwd string, managed bool, tool string, input map[string]any) string

// newHookConfigJudge builds the hook handler and audit store once for a
// connector and profile, so a table of rows pays the store and rule pack
// setup once and not once per row. The strict and permissive packs are
// installed for t and restored when t ends, so build the judge inside the
// subtest that uses it. managed marks one call as made under a managed
// enterprise install; that flag is process wide, so a judge is not used from
// parallel calls that mix modes.
func newHookConfigJudge(t *testing.T, conn, profile string) hookConfigJudge {
	t.Helper()
	return newHookConfigJudgeWith(t, conn, profile, true)
}

// newHookConfigJudgeWith is newHookConfigJudge; clientEvidence false sends a
// call without the hook client resolved-target header, as a hook command
// that does not resolve its targets does, so the gateway reads the shell
// call alone.
func newHookConfigJudgeWith(t *testing.T, conn, profile string, clientEvidence bool) hookConfigJudge {
	t.Helper()
	event := "PreToolUse"
	if conn == "opencode" {
		event = "tool.execute.before"
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = conn
	if profile == "strict" || profile == "permissive" {
		installToolCallCorpusProfileConnector(t, conn, profile)
		cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
	}
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	handler := api.handleAgentHook(conn)
	return func(cwd string, managed bool, tool string, input map[string]any) string {
		payload, err := json.Marshal(map[string]any{"session_id": "hook-config", "hook_event_name": event,
			"tool_name": tool, "cwd": cwd, "tool_input": input})
		if err != nil {
			return "payload not built: " + err.Error()
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/"+conn+"/hook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		if header := hookpaths.ResolveConnector(conn, "", event, payload); header != "" && clientEvidence {
			req.Header.Set(hookpaths.Header, header)
		}
		if conn == "codex" {
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
		}
		if managed {
			managedEnterpriseActive.Store(true)
			defer managedEnterpriseActive.Store(false)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Body.String()
	}
}

// hookConfigAction reads the verdict (block, alert or allow) out of a hook answer.
func hookConfigAction(got string) string {
	var answer struct {
		Action   string `json:"action"`
		Decision string `json:"decision"`
	}
	_ = json.Unmarshal([]byte(got), &answer)
	if answer.Action != "" {
		return answer.Action
	}
	for _, a := range []string{"block", "deny", "alert", "allow"} {
		if strings.Contains(got, `"`+a+`"`) {
			return a
		}
	}
	return "?"
}

// hookConfigCell is one profile and install mode a row is judged in.
type hookConfigCell struct {
	profile string
	managed bool
}

func (c hookConfigCell) mode() string {
	if c.managed {
		return "managed"
	}
	return "user"
}

// hookConfigBalancedAndStrictManaged are the two ends: the balanced default
// on a per-user install, and the strictest pack under the managed flag.
var hookConfigBalancedAndStrictManaged = []hookConfigCell{{"default", false}, {"strict", true}}

// forEachHookConfigCell runs check for each named row in each cell, with one
// judge and one audit store per cell. Per-user rows run in parallel; the
// managed flag is process wide, so managed rows run one at a time. The
// parallel children finish before the cell subtest returns, so the strict
// pack installed for the cell is restored after them.
func forEachHookConfigCell(t *testing.T, conn string, cells []hookConfigCell, names []string, check func(t *testing.T, judge hookConfigJudge, cell hookConfigCell, row int)) {
	t.Helper()
	for _, cell := range cells {
		t.Run(cell.profile+"/"+cell.mode(), func(t *testing.T) {
			judge := newHookConfigJudge(t, conn, cell.profile)
			for i, name := range names {
				t.Run(name, func(t *testing.T) {
					if !cell.managed {
						t.Parallel()
					}
					check(t, judge, cell, i)
				})
			}
		})
	}
}

// hookConfigShellRow is one Bash command and the verdict it gets in every
// cell of checkHookConfigShellRows: allow, block, or possible (an alert in
// the balanced default and a block under strict; a managed install leaves the
// agent config files to the vendor lock, so possible rows run per-user only).
type hookConfigShellRow struct{ name, command, want string }

// checkHookConfigShellRows judges each row in the two cells of
// hookConfigBalancedAndStrictManaged. The rows state behaviours that do not
// depend on the profile, so these two cells cover both ends.
func checkHookConfigShellRows(t *testing.T, h gap0048Home, rows []hookConfigShellRow) {
	t.Helper()
	checkHookConfigShellRowsIn(t, h, hookConfigBalancedAndStrictManaged, rows)
}

// checkHookConfigShellRowsIn is checkHookConfigShellRows for the given cells.
func checkHookConfigShellRowsIn(t *testing.T, h gap0048Home, cells []hookConfigCell, rows []hookConfigShellRow) {
	t.Helper()
	names := make([]string, len(rows))
	for i, row := range rows {
		names[i] = row.name
	}
	forEachHookConfigCell(t, "claudecode", cells, names, func(t *testing.T, judge hookConfigJudge, cell hookConfigCell, i int) {
		row := rows[i]
		want := row.want
		if want == "possible" {
			want = "alert"
			if cell.profile == "strict" {
				want = "block"
			}
		}
		if got := hookConfigAction(judge(h.project, cell.managed, "Bash", map[string]any{"command": row.command})); got != want {
			t.Errorf("got %s, want %s for %q", got, want, row.command)
		}
	})
}
