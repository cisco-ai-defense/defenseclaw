// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// moveOntoLinkParityRow is one shell call of a per-user action-mode
// gateway. {P} is the project (forward slashes), {M} the project as Git
// Bash spells a drive (/c/...). windowsOnly rows spell what only Windows
// reads; codexOnly rows are PowerShell, which Codex runs on Windows.
// noPowerShell rows spell a GNU mv option PowerShell refuses (Move-Item has
// no -T, and -f is ambiguous between -Force and -Filter): there the call
// fails before it runs, so Codex on Windows does not judge them.
type moveOntoLinkParityRow struct {
	name, command string
	block         bool
	windowsOnly   bool
	codexOnly     bool
	noPowerShell  bool
}

// judgeMoveOntoLinkParityRows runs rows through the Claude Code and Codex
// hooks of a per-user action-mode gateway, with and without the real hook
// client header, in a project that holds a.txt, src/, ordinary/f.txt and
// real links: slink (to the keys file), tlink (to ordinary/f.txt), sdlink
// (to the state directory), dssh (to ~/.ssh) and, on Windows, the junction
// jssh (to ~/.ssh). The same rows give the same verdict on Linux, macOS and
// Windows.
func judgeMoveOntoLinkParityRows(t *testing.T, rows []moveOntoLinkParityRow) {
	t.Helper()
	home := t.TempDir()
	project := filepath.Join(home, "project")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{filepath.Dir(keys), state, filepath.Join(project, "src"), filepath.Join(project, "ordinary")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{keys: "k\n", filepath.Join(state, "config.yaml"): "x: 1\n",
		filepath.Join(project, "a.txt"): "x\n", filepath.Join(project, "ordinary", "f.txt"): "x\n"} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"slink": keys, "tlink": filepath.Join(project, "ordinary", "f.txt"),
		"sdlink": state, "dssh": filepath.Dir(keys)} {
		if err := os.Symlink(target, filepath.Join(project, link)); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(project, "jssh"), filepath.Dir(keys)).CombinedOutput(); err != nil {
			t.Fatalf("junction: %v %s", err, out)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	slashProject := filepath.ToSlash(project)
	msysProject := slashProject
	if len(slashProject) > 2 && slashProject[1:2] == ":" {
		msysProject = "/" + strings.ToLower(slashProject[:1]) + slashProject[2:]
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, header := range []bool{true, false} {
			for _, row := range rows {
				name := connector + "/" + row.name
				if !header {
					name += "/no-header"
				}
				t.Run(name, func(t *testing.T) {
					if row.windowsOnly && runtime.GOOS != "windows" {
						t.Skip("a Windows spelling")
					}
					if row.codexOnly && (connector != "codex" || !codexShellRunsPowerShell) {
						t.Skip("PowerShell, which Codex runs on Windows")
					}
					if row.noPowerShell && connector == "codex" && codexShellRunsPowerShell {
						t.Skip("a GNU mv option PowerShell refuses")
					}
					command := strings.NewReplacer("{P}", slashProject, "{M}", msysProject).Replace(row.command)
					payload := mustJSON(t, map[string]any{"session_id": "mv-link-parity", "hook_event_name": "PreToolUse",
						"cwd": project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_mv",
						"tool_input": map[string]any{"command": command}})
					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					store, logger := testStoreAndLogger(t)
					api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
					req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
					req.Header.Set("Content-Type", "application/json")
					if header {
						req.Header.Set(hookpaths.Header, hookpaths.Resolve(payload))
					}
					if connector == "codex" {
						setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
					}
					recorder := httptest.NewRecorder()
					api.handleAgentHook(connector).ServeHTTP(recorder, req)
					got := recorder.Body.String()
					blocked := strings.HasPrefix(got, `{"action":"block"`)
					if !blocked && !strings.HasPrefix(got, `{"action":"allow"`) {
						t.Fatalf("%q: status %d body %.300s", command, recorder.Code, got)
					}
					if blocked != row.block {
						t.Fatalf("%q: block=%v, want %v: %.400s", command, blocked, row.block, got)
					}
					if row.block && !strings.Contains(got, "persistence.ssh_authorized_keys_command") && !strings.Contains(got, "tamper.detector_state_write") {
						t.Fatalf("%q: blocked by another rule: %.400s", command, got)
					}
				})
			}
		}
	}
}

// A plain mv onto an existing link to a file (or with -T onto a link to a
// directory) replaces the link entry and writes neither file, whatever the
// spelling of the destination: after a cd, with .. operands, cd-relative or
// absolute (rel-1-0-4:GAP-2559, cell L-win-J5-009). A write or copy through
// the link, a move onto the keys or state file itself, also through a linked
// directory or a junction, still blocks.
func TestMoveOntoLinkAfterCDMatchesAcrossOS(t *testing.T) {
	judgeMoveOntoLinkParityRows(t, []moveOntoLinkParityRow{
		{name: "V01 mv onto the link", command: `mv a.txt slink`},
		{name: "V02 cd then dotdot destination", command: `cd src && mv ../a.txt ../slink`},
		{name: "V03 mv -T onto the link", command: `mv -T a.txt slink`, noPowerShell: true},
		{name: "V04 mv -f onto the link", command: `mv -f a.txt slink`, noPowerShell: true},
		{name: "V05 dot slash", command: `mv a.txt ./slink`},
		{name: "V06 absolute destination", command: `mv a.txt {P}/slink`},
		{name: "V07 cd absolute then dotdot", command: `cd {P}/src && mv ../a.txt ../slink`},
		{name: "V08 cd then absolute destination", command: `cd src && mv ../a.txt {P}/slink`},
		{name: "V09 cd then mv -f dotdot", command: `cd src && mv -f ../a.txt ../slink`, noPowerShell: true},
		{name: "V10 cd then semicolon", command: `cd src; mv ../a.txt ../slink`},
		{name: "V11 cd up", command: `cd .. && mv project/a.txt project/slink`},
		{name: "V12 cd then onto a harmless link", command: `cd src && mv ../a.txt ../tlink`},
		{name: "V13 mv -T onto a link to a directory", command: `mv -T a.txt dssh`, noPowerShell: true},
		{name: "V14 cd then mv -T onto a link to a directory", command: `cd src && mv -T ../a.txt ../dssh`, noPowerShell: true},
		{name: "V15 ordinary", command: `cd src && mv ../a.txt ../b.txt`},
		{name: "V16 Git Bash drive destination", command: `mv a.txt {M}/slink`, windowsOnly: true},
		{name: "V17 cd Git Bash drive then dotdot", command: `cd {M}/src && mv ../a.txt ../slink`, windowsOnly: true},
		{name: "V18 mv -T onto a junction", command: `mv -T a.txt jssh`, windowsOnly: true, noPowerShell: true},
		{name: "V19 cd then mv -T onto a junction", command: `cd src && mv -T ../a.txt ../jssh`, windowsOnly: true, noPowerShell: true},
		{name: "B01 mv via a linked state dir", command: `mv a.txt sdlink/config.yaml`, block: true},
		{name: "B02 cd then via a linked state dir", command: `cd src && mv ../a.txt ../sdlink/config.yaml`, block: true},
		{name: "B03 write through the link", command: `echo x >> slink`, block: true},
		{name: "B04 copy through the link", command: `cp a.txt slink`, block: true},
		{name: "B05 cd then copy through the link", command: `cd src && cp ../a.txt ../slink`, block: true},
		{name: "B06 cd then write through the link", command: `cd src && echo x >> ../slink`, block: true},
		{name: "B07 mv via a linked .ssh", command: `mv a.txt dssh/authorized_keys`, block: true},
		{name: "B08 cd then via a linked .ssh", command: `cd src && mv ../a.txt ../dssh/authorized_keys`, block: true},
		{name: "B09 mv onto the keys file", command: `mv a.txt ~/.ssh/authorized_keys`, block: true},
		{name: "B10 cd .ssh then onto the keys name", command: `cd ~/.ssh && mv {P}/a.txt authorized_keys`, block: true},
		{name: "B11 cd then move then write", command: `cd src && mv ../a.txt ../slink; echo x >> ../slink`, block: true},
		{name: "B12 mv via a junction", command: `mv a.txt jssh/authorized_keys`, block: true, windowsOnly: true},
		{name: "B13 cd then via a junction", command: `cd src && mv ../a.txt ../jssh/authorized_keys`, block: true, windowsOnly: true},
		{name: "P01 Move-Item -Force onto the link", command: `Move-Item a.txt slink -Force`, codexOnly: true},
		{name: "P02 Move-Item named onto the link", command: `Move-Item -Path a.txt -Destination slink -Force`, codexOnly: true},
		{name: "P03 Set-Location then backslash dotdot", command: `Set-Location src; Move-Item ..\a.txt ..\slink -Force`, codexOnly: true},
		{name: "P04 mv alias with -Force", command: `mv a.txt slink -Force`, codexOnly: true},
		{name: "P05 Move-Item ordinary", command: `Move-Item a.txt b.txt`, codexOnly: true},
		{name: "Q01 Move-Item via a linked state dir", command: `Move-Item a.txt sdlink\config.yaml -Force`, block: true, codexOnly: true},
		{name: "Q02 Copy-Item through the link", command: `Copy-Item a.txt slink`, block: true, codexOnly: true},
		{name: "Q03 Add-Content through the link", command: `Add-Content slink x`, block: true, codexOnly: true},
		{name: "Q04 cd then Copy-Item through the link", command: `cd src; Copy-Item ../a.txt ../slink`, block: true, codexOnly: true},
		{name: "Q05 Move-Item via a junction", command: `Move-Item a.txt jssh\authorized_keys -Force`, block: true, codexOnly: true},
	})
}
