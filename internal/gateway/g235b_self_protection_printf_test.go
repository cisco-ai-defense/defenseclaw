// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// postSelfProtectionCell sends command to the hook route in one cell:
// per-user, managed with the hook client evidence, or managed with a home
// the gateway cannot read once the client evidence is built (blind), in
// the default or the strict rule pack.
func postSelfProtectionCell(t *testing.T, home, project, connector string, managed, blind, strict bool, command string) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	if strict {
		cfg.Guardrail.RulePack = "strict"
	}
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	body := mustJSON(t, map[string]any{"session_id": "self-protection-session", "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": command, "description": "d"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if managed {
		req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
		if blind {
			if err := os.Chmod(home, 0); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.Chmod(home, 0o700); err != nil {
					t.Fatal(err)
				}
			}()
		}
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	return recorder.Body.String()
}

// rel-1-0-6:GAP-0630, GAP-0601: printf assigns only through -v and through
// a %n conversion argument. An unknown format with no name argument assigns
// nothing, so HOME, USER and LOGNAME keep their values and every spelling
// of the DefenseClaw config path stays a protected write target in every
// cell and profile. The same forms into a project file stay allowed.
func TestG235bPrintfKeepsKnownHomeSpellingsForSelfProtection(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	t.Setenv("USER", filepath.Base(home))
	t.Setenv("LOGNAME", filepath.Base(home))
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(home) + "/"
	spellings := []struct{ prefix, name string }{
		{`"$HOME"`, "HOME"}, {`$HOME`, "HOME"}, {`${HOME}`, "HOME"},
		{parent + `$USER`, "USER"}, {parent + `${USER}`, "USER"}, {parent + `"$USER"`, "USER"},
		{parent + `$LOGNAME`, "LOGNAME"}, {parent + `${LOGNAME}`, "LOGNAME"},
	}
	forms := []string{
		`printf "$X" > {T}`,
		`printf "$X" >> {T}`,
		`printf -- "$X" > {T}`,
		`builtin printf "$X" > {T}`,
		`command printf "$X" > {T}`,
		`printf "$X" a b > {T}`,
		`printf "$X" "$X" > {T}`,
		`printf "$X"; echo x > {T}`,
		`printf "$X" && echo x > {T}`,
		`printf "$X" a; echo x > {T}`,
		`printf "%s$X" a; echo x > {T}`,
		`printf "%n" {V} > {T}`,
		`printf -v {V} x > {T}`,
		`read {V} < /dev/null > {T}`,
		`printf %s x > {T}`,
		`echo x > {T}`,
		`bash -c 'printf "$X" > {T}'`,
		`zsh -c 'printf "$X" > {T}'`,
		`bash -c 'printf "$X"; echo x > {T}'`,
		`zsh -c 'printf "$X"; echo x > {T}'`,
	}
	type row struct {
		name, command string
		protected     bool
	}
	var rows []row
	for _, spelling := range spellings {
		for _, form := range forms {
			command := strings.ReplaceAll(form, "{V}", spelling.name)
			rows = append(rows,
				row{spelling.prefix + "|" + form, strings.ReplaceAll(command, "{T}", spelling.prefix+"/.defenseclaw/config.yaml"), true},
				row{spelling.prefix + "|" + form + "|ordinary", strings.ReplaceAll(command, "{T}", spelling.prefix+"/proj/build.log"), false})
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, cell := range []struct{ managed, blind, strict bool }{
			{false, false, false}, {false, false, true},
			{true, false, false}, {true, false, true},
			{true, true, false}, {true, true, true},
		} {
			t.Run(fmt.Sprintf("%s/managed=%t/blind=%t/strict=%t", connector, cell.managed, cell.blind, cell.strict), func(t *testing.T) {
				for _, row := range rows {
					if !row.protected && cell.strict {
						continue
					}
					got := postSelfProtectionCell(t, home, project, connector, cell.managed, cell.blind, cell.strict, row.command)
					if row.protected {
						// A gateway that cannot read the home at all blocks
						// the state write under its own rule.
						if !strings.HasPrefix(got, `{"action":"block"`) ||
							!cell.blind && !strings.Contains(got, "tamper.detector_state_write") {
							t.Errorf("%s: %s = %.200s, want block tamper.detector_state_write", row.name, row.command, got)
						}
					} else if !strings.HasPrefix(got, `{"action":"allow"`) {
						t.Errorf("%s: %s = %.200s, want allow", row.name, row.command, got)
					}
				}
			})
		}
	}
}
