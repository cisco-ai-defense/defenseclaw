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
	pack := ""
	if strict {
		pack = "strict"
	}
	return postSelfProtectionPackCell(t, home, project, connector, pack, managed, blind, command)
}

// postSelfProtectionPackCell is postSelfProtectionCell with the rule pack
// named ("" is the default pack).
func postSelfProtectionPackCell(t *testing.T, home, project, connector, pack string, managed, blind bool, command string) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePack = pack
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

// rel-1-0-6:GAP-0630, GAP-0601: a managed gateway proves a redirect onto
// the DefenseClaw state from the targets its own reader names and finds the
// file each one opens in the hook client map. The client lists the targets
// of the same reader, so every HOME, USER and LOGNAME spelling of the config
// path stays a protected write target in every cell and profile, whatever
// an unknown printf format, printf -v, %n or read does to the values the
// other readers track. The same forms into a project file stay allowed.
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

// rel-1-0-6:GAP-0681, GAP-0630 review 1: a write to DefenseClaw state named
// through a known value ($HOME, and $USER or $LOGNAME as the last element
// of the home) is the write its literal spelling is, for an in-place editor
// operand and for a redirect through a link with an ordinary name, in
// per-user, managed and blind managed cells and in the default, strict and
// permissive packs. The same forms onto a project file, and through a link
// to a project file, stay allowed.
func TestG235bKnownValueStateTargetsInPlaceAndThroughLink(t *testing.T) {
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
	if err := os.Symlink(state, filepath.Join(home, "statealias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(project, "build.log"), filepath.Join(home, "projectalias")); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(home) + "/"
	spellings := []string{
		`"$HOME"`, `${HOME}`,
		parent + `$USER`, parent + `${USER}`, parent + `"$USER"`,
		parent + `$LOGNAME`, parent + `${LOGNAME}`, parent + `"$LOGNAME"`,
	}
	edits := []string{
		`sed -i d {T}`,
		`sed -i s/a/b/ {T}`,
		`sed -i.bak d {T}`,
		`sed --in-place d {T}`,
		`sed -i -e d {T}`,
		`sed -n -i p {T}`,
		`perl -pi -e 1 {T}`,
		`bash -c "echo x > {T}"`,
		`bash -c "sed -i d {T}"`,
		`sh -c "printf x > {T}"`,
	}
	redirects := []string{
		`printf "$X" > {L}`,
		`echo x >> {L}`,
		`: > {L}`,
		`printf "$X" a; echo x > {L}`,
		`bash -c "echo x > {L}"`,
	}
	type row struct {
		command   string
		protected bool
	}
	var rows []row
	for _, spelling := range spellings {
		for _, form := range edits {
			rows = append(rows,
				row{strings.ReplaceAll(form, "{T}", spelling+"/.defenseclaw/config.yaml"), true},
				row{strings.ReplaceAll(form, "{T}", spelling+"/proj/build.log"), false})
		}
		for _, form := range redirects {
			rows = append(rows,
				row{strings.ReplaceAll(form, "{L}", spelling+"/statealias"), true},
				row{strings.ReplaceAll(form, "{L}", spelling+"/projectalias"), false})
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, pack := range []string{"", "strict", "permissive"} {
			for _, cell := range []struct{ managed, blind bool }{{false, false}, {true, false}, {true, true}} {
				t.Run(fmt.Sprintf("%s/pack=%s/managed=%t/blind=%t", connector, pack, cell.managed, cell.blind), func(t *testing.T) {
					for _, row := range rows {
						if !row.protected && pack == "strict" {
							continue
						}
						got := postSelfProtectionPackCell(t, home, project, connector, pack, cell.managed, cell.blind, row.command)
						if row.protected {
							if !strings.HasPrefix(got, `{"action":"block"`) ||
								!cell.blind && !strings.Contains(got, "tamper.detector_state_write") {
								t.Errorf("%s = %.200s, want block tamper.detector_state_write", row.command, got)
							}
						} else if !strings.HasPrefix(got, `{"action":"allow"`) {
							t.Errorf("%s = %.200s, want allow", row.command, got)
						}
					}
				})
			}
		}
	}
}

// rel-1-0-6:GAP-0681, GAP-0630, GAP-0601 review 2: an in-place editor entry
// whose directory is a link to the DefenseClaw state folder, and a sed
// --follow-symlinks operand that is a link to a state file, edit state in
// every cell, managed and blind managed included, however the home is
// spelled. A value the command binds first names the file of that value:
// USER=other; sed -i d <parent>/$USER/aliasdir/config.yaml edits the
// sibling file of other and stays allowed, as does a shell body that
// inherits such a binding, and sed -i on a final link (the editor replaces
// the link).
func TestG235bKnownValueBindingsAndLinkedEditorEntries(t *testing.T) {
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
	if err := os.Symlink(state, filepath.Join(home, "statealias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(state), filepath.Join(home, "aliasdir")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(home), "other")
	for _, dir := range []string{filepath.Join(other, "aliasdir"), filepath.Join(other, ".defenseclaw")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(other, "statealias"), filepath.Join(other, "aliasdir", "config.yaml"),
		filepath.Join(other, ".defenseclaw", "config.yaml")} {
		if err := os.WriteFile(name, []byte("other\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	parent := filepath.Dir(home) + "/"
	type row struct {
		command               string
		protected, perUserOff bool
	}
	var rows []row
	for _, spelling := range []string{home, `"$HOME"`, `${HOME}`, parent + `$USER`, parent + `${LOGNAME}`} {
		for _, form := range []string{
			`sed -i d {S}/aliasdir/config.yaml`,
			`sed --in-place d {S}/aliasdir/config.yaml`,
			`perl -pi -e 1 {S}/aliasdir/config.yaml`,
			`sed -i -e "s/USER=a/USER=b/" {S}/aliasdir/config.yaml`,
			`echo USER=a; sed -i d {S}/aliasdir/config.yaml`,
			`sed -i --follow-symlinks d {S}/statealias`,
			`bash -c "sed -i d {S}/aliasdir/config.yaml"`,
		} {
			rows = append(rows, row{command: strings.ReplaceAll(form, "{S}", spelling), protected: true})
		}
	}
	rows = append(rows,
		row{command: `cd "$HOME" && sed -i d aliasdir/config.yaml`, protected: true},
		row{command: `USER=other; USER=` + filepath.Base(home) + `; sed -i d ` + parent + `$USER/aliasdir/config.yaml`, protected: true},
		row{command: `USER=other; sed -i d ` + parent + `$USER/aliasdir/config.yaml`},
		row{command: `LOGNAME=other; sed -i d ` + parent + `$LOGNAME/aliasdir/config.yaml`},
		row{command: `USER=other; sed -i.bak d ` + parent + `$USER/aliasdir/config.yaml`},
		row{command: `USER=other; sed -i d ` + parent + `$USER/.defenseclaw/config.yaml`},
		row{command: `export LOGNAME=other; sed -i d ` + parent + `$LOGNAME/.defenseclaw/config.yaml`},
		row{command: `USER=other bash -c 'sed -i d ` + parent + `$USER/.defenseclaw/config.yaml'`},
		row{command: `sed -i d ` + parent + `$USER/statealias`},
		row{command: `sed -i d "$HOME"/statealias`},
		// Per-user, the gateway reads the body in the child pass as the
		// home spelling on the base as well; only the hook client map
		// reading changed here.
		row{command: `USER=other bash -c 'printf x > ` + parent + `$USER/statealias'`, perUserOff: true},
		row{command: `USER=other bash -lc 'printf x > ` + parent + `$USER/statealias'`, perUserOff: true},
		row{command: `env USER=other bash -c 'printf x > ` + parent + `$USER/statealias'`, perUserOff: true},
	)
	for _, connector := range []string{"claudecode", "codex"} {
		for _, pack := range []string{"", "strict", "permissive"} {
			for _, cell := range []struct{ managed, blind bool }{{false, false}, {true, false}, {true, true}} {
				t.Run(fmt.Sprintf("%s/pack=%s/managed=%t/blind=%t", connector, pack, cell.managed, cell.blind), func(t *testing.T) {
					for _, row := range rows {
						// A strict pack fails closed once the home cannot be
						// read (blind); ordinary rows are judged elsewhere.
						if row.perUserOff && !cell.managed || !row.protected && pack == "strict" && cell.blind {
							continue
						}
						got := postSelfProtectionPackCell(t, home, project, connector, pack, cell.managed, cell.blind, row.command)
						if row.protected {
							if !strings.HasPrefix(got, `{"action":"block"`) ||
								!cell.blind && !strings.Contains(got, "tamper.detector_state_write") {
								t.Errorf("%s = %.200s, want block tamper.detector_state_write", row.command, got)
							}
						} else if !strings.HasPrefix(got, `{"action":"allow"`) {
							t.Errorf("%s = %.200s, want allow", row.command, got)
						}
					}
				})
			}
		}
	}
}
