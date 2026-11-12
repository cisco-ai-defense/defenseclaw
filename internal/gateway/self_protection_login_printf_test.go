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

// postSelfProtectionPackCell sends command to the hook route in one cell:
// per-user, managed with the hook client evidence, or managed with a home
// the gateway cannot read once the client evidence is built (blind), under
// the rule pack named ("" is the default pack).
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

// g235bCell is one cell of a G235b rotation: the connector, the rule pack
// ("" is the default pack) and the route (per-user, managed with the hook
// client evidence, or blind managed: a home the gateway cannot read).
type g235bCell struct {
	connector, pack string
	managed, blind  bool
}

func (c g235bCell) String() string {
	return fmt.Sprintf("%s/pack=%s/managed=%t/blind=%t", c.connector, c.pack, c.managed, c.blind)
}

// g235bRow is one command of a G235b rotation: a protected row writes
// DefenseClaw state and blocks, an ordinary row stays allowed.
type g235bRow struct {
	name, command string
	protected     bool
}

// g235bRotate judges rows in a rotation over the cells (both connectors,
// packs, per-user and managed, and blind managed when blind is set) instead
// of the rows x cells product (owner TEST BUDGET 2026-11-10: one hook call
// costs about 100 ms under -race, and the products ran 2 to 5 minutes).
//
// Every row is judged twice, once per-user and once managed, and the two
// calls use different connectors, so every row meets both connectors and
// both routes. A protected row has one of its two calls in the strict pack
// (per-user and managed in turn) and the other in a non-strict pack in
// turn. An ordinary row is never judged strict (the products skipped it
// there too) and shares the non-strict cell of the protected row with its
// index, so an attack and its benign twin meet in the same cell. With blind,
// every second row is also judged blind managed, packs and connectors in
// turn. The plan check fails the test when a row misses a route or a strict
// call, when a cell has no protected row, or when a non-strict cell has no
// ordinary row, so the rotation cannot leave a cell or a row unjudged.
func g235bRotate(t *testing.T, rows []g235bRow, packs []string, blind bool, judge func(t *testing.T, cell g235bCell, row g235bRow)) {
	t.Helper()
	connectors := []string{"claudecode", "codex"}
	var nonStrict []string
	hasStrict := false
	for _, pack := range packs {
		if pack == "strict" {
			hasStrict = true
		} else {
			nonStrict = append(nonStrict, pack)
		}
	}
	n := len(nonStrict)
	if n == 0 {
		t.Fatal("g235bRotate needs a non-strict pack")
	}
	plan := map[g235bCell][]g235bRow{}
	add := func(cell g235bCell, row g235bRow) { plan[cell] = append(plan[cell], row) }
	protected, ordinary := 0, 0
	for _, row := range rows {
		k := ordinary
		if row.protected {
			k = protected
			protected++
		} else {
			ordinary++
		}
		strictPerUser := k%2 == 0
		pack := nonStrict[(k/2)%n]
		other := nonStrict[(k/2+1)%n]
		perUser := g235bCell{connector: connectors[(k/(2*n))%2]}
		managed := g235bCell{connector: connectors[1-(k/(2*n))%2], managed: true}
		switch {
		case row.protected && hasStrict && strictPerUser:
			perUser.pack, managed.pack = "strict", pack
		case row.protected && hasStrict:
			perUser.pack, managed.pack = pack, "strict"
		case strictPerUser:
			perUser.pack, managed.pack = other, pack
		default:
			perUser.pack, managed.pack = pack, other
		}
		add(perUser, row)
		add(managed, row)
		if blind && k%2 == 0 {
			cell := g235bCell{connector: connectors[(k/(2*len(packs)))%2], pack: packs[(k/2)%len(packs)], managed: true, blind: true}
			if !row.protected && cell.pack == "strict" {
				cell.pack = nonStrict[(k/2)%n]
			}
			add(cell, row)
		}
	}
	// The plan check: every row on both routes (and in strict when it is
	// protected), every cell with an attack, every non-strict cell with a
	// benign row.
	routes := map[string]map[string]bool{}
	for cell, judged := range plan {
		for _, row := range judged {
			if routes[row.command] == nil {
				routes[row.command] = map[string]bool{}
			}
			routes[row.command][fmt.Sprintf("managed=%t", cell.managed && !cell.blind)] = true
			routes[row.command]["pack="+cell.pack] = true
		}
	}
	for _, row := range rows {
		seen := routes[row.command]
		if !seen["managed=false"] || !seen["managed=true"] || row.protected && hasStrict && !seen["pack=strict"] {
			t.Fatalf("rotation plan leaves %s (%s) unjudged in a route or in strict: %v", row.name, row.command, seen)
		}
	}
	var cells []g235bCell
	for _, connector := range connectors {
		for _, pack := range packs {
			for _, route := range []struct{ managed, blind bool }{{false, false}, {true, false}, {true, true}} {
				if route.blind && !blind {
					continue
				}
				cell := g235bCell{connector, pack, route.managed, route.blind}
				attack, benign := false, false
				for _, row := range plan[cell] {
					attack = attack || row.protected
					benign = benign || !row.protected
				}
				if !attack || pack != "strict" && !benign {
					t.Fatalf("rotation plan leaves cell %s without an attack or a benign row (%d rows)", cell, len(plan[cell]))
				}
				cells = append(cells, cell)
			}
		}
	}
	for _, cell := range cells {
		t.Run(cell.String(), func(t *testing.T) {
			for _, row := range plan[cell] {
				judge(t, cell, row)
			}
		})
	}
}

// rel-1-0-6:GAP-0630, GAP-0601: a managed gateway proves a redirect onto
// the DefenseClaw state from the targets its own reader names and finds the
// file each one opens in the hook client map. The client lists the targets
// of the same reader, so every HOME, USER and LOGNAME spelling of the config
// path stays a protected write target in every cell and profile, whatever
// an unknown printf format, printf -v, %n or read does to the values the
// other readers track. The same forms into a project file stay allowed.
//
// Every form is judged with a spelling in turn (form i takes spelling i mod
// 8, so each spelling meets two or three forms), and each form that binds
// a name ({V}: %n, printf -v, read) is judged with a HOME, a USER and a
// LOGNAME spelling, each with its project-file twin; g235bRotate spreads
// the rows over the cells.
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
	var rows []g235bRow
	for i, form := range forms {
		picks := []int{i % len(spellings)}
		if strings.Contains(form, "{V}") {
			// One spelling of each name: HOME (0-2), USER (3-5), LOGNAME (6-7).
			picks = []int{i % 3, 3 + i%3, 6 + i%2}
		}
		for _, pick := range picks {
			spelling := spellings[pick]
			command := strings.ReplaceAll(form, "{V}", spelling.name)
			rows = append(rows,
				g235bRow{spelling.prefix + "|" + form, strings.ReplaceAll(command, "{T}", spelling.prefix+"/.defenseclaw/config.yaml"), true},
				g235bRow{spelling.prefix + "|" + form + "|ordinary", strings.ReplaceAll(command, "{T}", spelling.prefix+"/proj/build.log"), false})
		}
	}
	g235bRotate(t, rows, []string{"", "strict"}, true, func(t *testing.T, cell g235bCell, row g235bRow) {
		got := postSelfProtectionPackCell(t, home, project, cell.connector, cell.pack, cell.managed, cell.blind, row.command)
		if row.protected {
			// A gateway that cannot read the home at all blocks the state
			// write under its own rule.
			if !strings.HasPrefix(got, `{"action":"block"`) ||
				!cell.blind && !strings.Contains(got, "tamper.detector_state_write") {
				t.Errorf("%s: %s = %.200s, want block tamper.detector_state_write", row.name, row.command, got)
			}
		} else if !strings.HasPrefix(got, `{"action":"allow"`) {
			t.Errorf("%s: %s = %.200s, want allow", row.name, row.command, got)
		}
	})
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
