// Shared judge for the agent hook config regression tests.

package gateway

import (
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
		payload := mustJSON(t, map[string]any{"session_id": "rv3gx048", "hook_event_name": event,
			"tool_name": tool, "cwd": cwd, "tool_input": input})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/"+conn+"/hook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		if header := hookpaths.ResolveConnector(conn, "", event, payload); header != "" {
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

// rv3Judge is a one-call newHookConfigJudge.
func rv3Judge(t *testing.T, conn, profile, cwd string, managed bool, tool string, input map[string]any) string {
	t.Helper()
	return newHookConfigJudge(t, conn, profile)(cwd, managed, tool, input)
}

// hookConfigShellRow is one Bash command and the verdict it gets in every
// cell of checkHookConfigShellRows.
type hookConfigShellRow struct{ name, command, want string }

// checkHookConfigShellRows judges each row in two cells: the default pack for
// a per-user install and the strict pack for a managed install. The rows
// state behaviours that do not depend on the profile, so these two cells
// cover both ends (the balanced default, and the strictest pack under the
// managed flag) with one handler per cell. Per-user rows run in parallel; the
// managed flag is process wide, so managed rows run one at a time.
func checkHookConfigShellRows(t *testing.T, h gap0048Home, rows []hookConfigShellRow) {
	t.Helper()
	for _, cell := range []struct {
		profile string
		managed bool
	}{{"default", false}, {"strict", true}} {
		mode := "user"
		if cell.managed {
			mode = "managed"
		}
		t.Run(cell.profile+"/"+mode, func(t *testing.T) {
			judge := newHookConfigJudge(t, "claudecode", cell.profile)
			for _, row := range rows {
				t.Run(row.name, func(t *testing.T) {
					if !cell.managed {
						t.Parallel()
					}
					got := rv2Action(judge(h.project, cell.managed, "Bash", map[string]any{"command": row.command}))
					if got != row.want {
						t.Errorf("got %s, want %s for %q", got, row.want, row.command)
					}
				})
			}
		})
	}
}
