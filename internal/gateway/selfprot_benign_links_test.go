// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// selfProtRow is one shell command of the benign link and copy forms and
// the verdict an action-mode gateway must give it.
type selfProtRow struct{ id, cmd, want string }

// selfProtVerdict posts cmd to an action-mode gateway for connector, behind
// ProtectHome (managed, with the real hook client header) or per-user. The
// project holds build/out, src, ordinary and keylink (a link to the keys
// decoy); a link named dclink to the DefenseClaw state is added for BL rows.
func selfProtVerdict(t *testing.T, r selfProtRow, managed bool, connector string) string {
	t.Helper()
	f := newB36ManagedHookFixture(t)
	for _, dir := range []string{"build/out", "src", "ordinary", "../.defenseclaw"} {
		if err := os.MkdirAll(filepath.Join(f.project, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"a.txt", "b.txt", "README.md", "SOUL.md", "src/a.txt", "src/main.go", "build/x.o", "ordinary/o.txt", "../.defenseclaw/config.yaml"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if strings.HasPrefix(r.id, "BL") {
		if err := os.Symlink("../.defenseclaw", filepath.Join(f.project, "dclink")); err != nil {
			t.Fatal(err)
		}
	}
	payload := f.payload(t, r.cmd)
	header := f.clientHeader(t, payload)
	if managed {
		return f.post(t, connector, payload, header)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	switch body := recorder.Body.String(); {
	case strings.HasPrefix(body, `{"action":"block"`):
		return "block"
	case strings.HasPrefix(body, `{"action":"allow"`):
		return "allow"
	default:
		return "status " + recorder.Result().Status
	}
}

func checkSelfProtRows(t *testing.T, rows []selfProtRow, connectors ...string) {
	t.Helper()
	for _, managed := range []bool{true, false} {
		for _, connector := range connectors {
			for _, r := range rows {
				if got := selfProtVerdict(t, r, managed, connector); got != r.want {
					t.Errorf("%s managed=%v %s: %q = %s, want %s", r.id, managed, connector, r.cmd, got, r.want)
				}
			}
		}
	}
}

// A plain cp writes its own destination: that write skips only its own
// copy scope, also when the cp runs in a literal sh -c body (GAP-2582).
func TestSelfProtCopyOwnDestinationIsOrdinary(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"B01", `ln -s build/out bin && cp -a build/x.o dist.o`, "allow"},
		{"B07", `ln -s build/out bin && cp -a src dist && cp -a dist dist2`, "allow"},
		{"N03", `sh -c "ln -s build/out bin && cp -a build dist"`, "allow"},
		{"T10", `ln -s ../.ssh/authorized_keys k; cp -a k dist; echo key >> dist`, "block"},
		{"T13", `ln -s ../.ssh k; cp -a build dist; cp -a src/a.txt k/authorized_keys`, "block"},
		{"T02", `sh -c "ln -s ../.ssh k && cp -a src/a.txt k/authorized_keys"`, "block"},
	}, "claudecode", "codex")
}

// Behind ProtectHome, links unknown only inside copy scopes that cannot
// reach an operand are answered by the hook client walk (GAP-2582, GAP-2579).
func TestSelfProtManagedAliasOutsideCopyScope(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"N03p", `ln -s build/out bin && cp -a build dist`, "allow"},
		{"B03", `ln -sf ../src/a.txt link.txt && cp -a src out`, "allow"},
		{"B34", `nohup cp -r src src-bak && ln -s src-bak/main.go x.go`, "allow"},
		{"T18", `ln -s build/out bin && cp -a build dist && echo key >> keylink`, "block"},
		{"T21", `ln -s ~/.ssh build/k && cp -a build dist && echo key >> dist/k/authorized_keys`, "block"},
	}, "claudecode", "codex")
}

// env -C DIR ln runs ln in DIR, as a copy child does (GAP-2579, GAP-2576).
func TestSelfProtEnvChdirLinkIsPlaced(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"B21", `env -C ~/project ln -s build/out bin`, "allow"},
		{"L08", `env -C ~/project ln -sf ordinary/o.txt ln2.go; cp a.txt ln2.go`, "allow"},
		{"E02", `env -C ~/project ln -sf ../.ssh/authorized_keys ln3; cp a.txt ln3`, "block"},
		{"E03", `env -C ~/project ln -s ../.ssh ks; cp a.txt ks/authorized_keys`, "block"},
		{"A09", `env -C ~ ln -s .ssh/authorized_keys project/k7`, "block"},
	}, "claudecode", "codex")
}

// The own destination of a copy after a placed directory change is read
// against its own scope (GAP-2579).
func TestSelfProtCopyAfterDirectoryChange(t *testing.T) {
	checkSelfProtRows(t, []selfProtRow{
		{"B11", `env -C ~ cp -r project project-bak`, "allow"},
		{"E01", `env -C ~ cp -r project project-bak; echo key >> ~/project-bak/keylink`, "block"},
		{"E05", `env -C ~ cp -a project/keylink kl2; echo key >> ~/kl2`, "block"},
	}, "claudecode", "codex")
}