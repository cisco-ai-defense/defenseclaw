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

// linkedScriptFolder writes the writer wk.sh and the ordinary ok.sh below the
// project, and names the folder that holds them through a chain of links:
// the folder c below the project is a link to the real folder: a relative
// link (links below zero), an absolute one (zero) or the first of a chain of
// links links outside the project, the last of which is the real folder.
func linkedScriptFolder(t *testing.T, f b36ManagedHookFixture, links int) {
	t.Helper()
	real := filepath.Join(f.project, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "wk.sh"), []byte("echo marker >> $HOME/.ssh/authorized_keys\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// safe.sh is the file the link chain helper opens to prove the chain works.
	for _, name := range []string{"ok.sh", "safe.sh"} {
		if err := os.WriteFile(filepath.Join(real, name), []byte("echo ordinary >> report.txt\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := "real"
	switch {
	case links == 0:
		// One link inside the working folder, to an absolute path.
		target = real
	case links > 0:
		target = gatewayLinkChain(t, links, real)
	}
	if err := os.Symlink(target, filepath.Join(f.project, "c")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
}

// TestSourcedWriterNamedThroughLinksIsBlockedInEverySpelling: the dot builtin
// and source read a script named by a relative, absolute or home-relative
// path through any number of folder links the system opens (40 on Linux, 32
// on macOS, 63 on Windows), top level or inside bash -c or sh -c, per-user
// and managed, and a write it makes to the keys file is blocked; the
// ordinary script behind the same links is allowed (rel-1-0-9:GAP-1013,
// GAP-1015, GAP-1017). A path through more links than the system opens is
// judged by the tier, see TestScriptNamedThroughLinksOutsideTheWorkingFolderIsReadOrUnread.
func TestSourcedWriterNamedThroughLinksIsBlockedInEverySpelling(t *testing.T) {
	limit := hookpaths.SystemLinkLimit()
	for _, links := range []int{-1, 0, 1, 2, 3, 8, 9, 10, 31, limit - 1} {
		t.Run(fmt.Sprintf("%d links", links), func(t *testing.T) {
			setup := func(t *testing.T, f b36ManagedHookFixture) { linkedScriptFolder(t, f, links) }
			var rows []r106Reader2Row
			for _, builtin := range []string{".", "source"} {
				rows = append(rows,
					r106Reader2Row{builtin + " relative", "project", builtin + ` ./c/wk.sh`, "block"},
					r106Reader2Row{builtin + " relative without dot", "project", builtin + ` c/wk.sh`, "block"},
					r106Reader2Row{builtin + " absolute", "project", builtin + ` {P}/c/wk.sh`, "block"},
					r106Reader2Row{builtin + " home-relative", "home", builtin + ` ~/project/c/wk.sh`, "block"},
					r106Reader2Row{builtin + " bash -c", "project", `bash -c "` + builtin + ` ./c/wk.sh"`, "block"},
					r106Reader2Row{builtin + " sh -c absolute", "project", `sh -c "` + builtin + ` {P}/c/wk.sh"`, "block"},
					r106Reader2Row{builtin + " ordinary relative", "project", builtin + ` ./c/ok.sh`, "allow"},
					r106Reader2Row{builtin + " ordinary absolute", "project", builtin + ` {P}/c/ok.sh`, "allow"},
					r106Reader2Row{builtin + " ordinary home-relative", "home", builtin + ` ~/project/c/ok.sh`, "allow"},
					r106Reader2Row{builtin + " ordinary bash -c", "project", `bash -c "` + builtin + ` ./c/ok.sh"`, "allow"},
				)
			}
			r106Reader2CheckWith(t, rows, setup)
		})
	}
}

// TestSourcedWriterIsJudgedWhereverItSitsInTheCommand: the verdict on a
// sourced writer behind folder links does not depend on the shell wrapper or
// the list it sits in. A block stops the whole call before any of it runs,
// so a source that a list or an exit may keep from running is judged as if
// it runs, at the top level, in a bash -c string and around one, exactly as
// the same command without the links is (rel-1-0-9:GAP-1013).
func TestSourcedWriterIsJudgedWhereverItSitsInTheCommand(t *testing.T) {
	setup := func(t *testing.T, f b36ManagedHookFixture) { linkedScriptFolder(t, f, 3) }
	var rows []r106Reader2Row
	for _, dir := range []string{"c", "real"} {
		rows = append(rows,
			r106Reader2Row{dir + " false and", "project", `false && . ./` + dir + `/wk.sh`, "block"},
			r106Reader2Row{dir + " true or", "project", `true || . ./` + dir + `/wk.sh`, "block"},
			r106Reader2Row{dir + " exit before", "project", `exit 0; . ./` + dir + `/wk.sh`, "block"},
			r106Reader2Row{dir + " wrapped false and", "project", `bash -c "false && . ./` + dir + `/wk.sh"`, "block"},
			r106Reader2Row{dir + " wrapped true or", "project", `bash -c "true || . ./` + dir + `/wk.sh"`, "block"},
			r106Reader2Row{dir + " wrapped exit before", "project", `bash -c "exit 0; . ./` + dir + `/wk.sh"`, "block"},
			r106Reader2Row{dir + " nested false and", "project", `bash -c "sh -c 'false && . ./` + dir + `/wk.sh'"`, "block"},
			r106Reader2Row{dir + " wrapper after false and", "project", `false && bash -c ". ./` + dir + `/wk.sh"`, "block"},
			r106Reader2Row{dir + " wrapper after exit", "project", `exit 0; bash -c ". ./` + dir + `/wk.sh"`, "block"},
			r106Reader2Row{dir + " combined flags", "project", `bash -ec ". ./` + dir + `/wk.sh"`, "block"},
		)
	}
	rows = append(rows,
		r106Reader2Row{"ordinary wrapped false and", "project", `bash -c "false && . ./c/ok.sh"`, "allow"},
		r106Reader2Row{"ordinary wrapper after exit", "project", `exit 0; bash -c ". ./c/ok.sh"`, "allow"},
		r106Reader2Row{"ordinary combined flags", "project", `bash -ec ". ./c/ok.sh"`, "allow"},
	)
	r106Reader2CheckWith(t, rows, setup)
}

// TestSourcedWriterBehindLinksIsBlockedUnderAnyShellLauncher: a login or
// interactive shell, zsh, and a sudo, env, nohup, timeout, command or exec
// launcher around a shell command string read the script behind folder links
// and judge it as the bare bash -c does, with or without the links
// (rel-1-0-9:GAP-1021).
//
// Every launcher row (through the links, without them, and the ordinary
// script through them) is judged per user and managed, once, not for every
// link count and connector, the owner's test budget: row x of a launcher is
// judged at link count x mod 3 by connector x mod 2 (x = launcher index +
// row kind), so each link count and each connector judges every row kind,
// and every launcher meets all three kinds. One fixture serves each link
// count; the rows only read it. The check at the end shows that every link
// count and connector judged all three kinds.
func TestSourcedWriterBehindLinksIsBlockedUnderAnyShellLauncher(t *testing.T) {
	launchers := []string{
		`bash -c`, `bash -l -c`, `bash -lc`, `bash --login -c`, `bash -i -c`, `bash -ec`, `bash -lec`,
		`sh -c`, `zsh -c`, `zsh -ic`,
		`sudo bash -c`, `sudo -u root bash -c`, `env bash -c`, `env -i bash -c`, `env A=1 sh -c`,
		`sudo env bash -c`, `nohup bash -c`, `timeout 5 bash -c`, `command bash -c`, `exec bash -c`,
	}
	linkCounts := []int{3, 9, hookpaths.SystemLinkLimit() - 1}
	connectors := []string{"claudecode", "codex"}
	kinds := []func(launcher string) r106Reader2Row{
		func(launcher string) r106Reader2Row {
			return r106Reader2Row{launcher + " through links", "project", launcher + ` ". ./c/wk.sh"`, "block"}
		},
		func(launcher string) r106Reader2Row {
			return r106Reader2Row{launcher + " without links", "project", launcher + ` ". ./real/wk.sh"`, "block"}
		},
		func(launcher string) r106Reader2Row {
			return r106Reader2Row{launcher + " ordinary through links", "project", launcher + ` ". ./c/ok.sh"`, "allow"}
		},
	}
	judged := map[[3]int]bool{}
	for li, links := range linkCounts {
		t.Run(fmt.Sprintf("%d links", links), func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			linkedScriptFolder(t, f, links)
			for j, launcher := range launchers {
				for kind, row := range kinds {
					x := j + kind
					if x%len(linkCounts) != li {
						continue
					}
					ci := x % len(connectors)
					judged[[3]int{li, ci, kind}] = true
					sourcedWriterLauncherCheck(t, f, connectors[ci], row(launcher))
				}
			}
		})
	}
	for li, links := range linkCounts {
		for ci, connector := range connectors {
			for kind := range kinds {
				if !judged[[3]int{li, ci, kind}] {
					t.Errorf("%d links, %s: row kind %d never judged; the rotation must cover it", links, connector, kind)
				}
			}
		}
	}
}

// sourcedWriterLauncherCheck is one row of r106Reader2CheckWith for one
// connector on a fixture the caller set up once: the row through a per-user
// action-mode gateway and a managed one (home hidden, the real hook client
// header).
func sourcedWriterLauncherCheck(t *testing.T, f b36ManagedHookFixture, connector string, row r106Reader2Row) {
	t.Helper()
	cwd := f.project
	if row.where == "home" {
		cwd = f.home
	}
	command := strings.NewReplacer("{P}", f.project, "{K}", f.keys, "{H}", f.home).Replace(row.command)
	payload := mustJSON(t, map[string]any{"session_id": "r106", "hook_event_name": "PreToolUse", "cwd": cwd,
		"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_r106",
		"tool_input": map[string]any{"command": command, "description": "Run test fixture command"}})
	header := f.clientHeader(t, payload)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	req.Header.Set(hookpaths.Header, header)
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	perUser := "allow"
	if body := recorder.Body.String(); strings.Contains(body, `"deny"`) || strings.Contains(body, `"block"`) {
		perUser = "block"
	}
	managed := f.post(t, connector, payload, header)
	if err := os.Chmod(f.homes, 0o700); err != nil {
		t.Fatal(err)
	}
	if perUser != row.want || managed != row.want {
		t.Errorf("%s %s: per-user %s, managed %s, want %s", connector, row.name, perUser, managed, row.want)
	}
}
