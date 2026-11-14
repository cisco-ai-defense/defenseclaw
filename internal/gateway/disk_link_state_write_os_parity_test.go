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

// diskLinkStateRow is one Claude Code Bash call judged by a per-user
// action-mode gateway (default pack). {E} is a folder outside the home that
// holds y, a disk link to ~/.defenseclaw, x, a disk link to ~/.ssh, and ok, a
// plain folder; {EM} is {E} as Git Bash spells a drive (/c/...), {EB} with
// backslashes, {J} a folder outside the home whose entry y is a directory
// junction to ~/.defenseclaw (Windows only). rule is the rule a blocked row
// names ("" for an allowed row).
type diskLinkStateRow struct {
	name, command, rule string
	windowsOnly         bool
}

const (
	diskLinkStateRule = "tamper.detector_state_write"
	diskLinkKeysRule  = "persistence.ssh_authorized_keys_command"
	// diskLinkAnyRule: either rule. A cd into a link that an inner shell
	// makes is also read by the keys reader, which cannot place the cd, so
	// the call may name that rule (Linux and Windows alike).
	diskLinkAnyRule = "any"
	// diskLinkUncertain: a cd into a link the call makes inside a shell body, the
	// target of which the walk cannot place: the default pack alerts on the keys
	// rule (rel-1-0-10:GAP-0350).
	diskLinkUncertain = "uncertain"
)

// judgeDiskLinkStateRows runs rows through the Claude Code hook as the
// installed hook sends them: once with the client's resolved write targets
// (the native hook resolves them as the user) and once without them.
func judgeDiskLinkStateRows(t *testing.T, rows []diskLinkStateRow) {
	t.Helper()
	home := t.TempDir()
	ext := t.TempDir()
	project := filepath.Join(home, "proj")
	state := filepath.Join(home, ".defenseclaw")
	keys := filepath.Join(home, ".ssh")
	for _, dir := range []string{state, keys, project, filepath.Join(ext, "ok")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{filepath.Join(state, "config.yaml"): "x: 1\n",
		filepath.Join(keys, "authorized_keys"): "k\n", filepath.Join(project, "notes.txt"): "x\n",
		filepath.Join(ext, "ok", "a.txt"): "x\n"} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(state, filepath.Join(ext, "y")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(ext, "x")); err != nil {
		t.Fatal(err)
	}
	junctions := ""
	if runtime.GOOS == "windows" {
		junctions = t.TempDir()
		out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(junctions, "y"), state).CombinedOutput()
		if err != nil {
			t.Fatalf("mklink /J: %v: %s", err, out)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	msys := func(value string) string {
		slashed := filepath.ToSlash(value)
		if len(slashed) > 2 && slashed[1:2] == ":" {
			return "/" + strings.ToLower(slashed[:1]) + slashed[2:]
		}
		return slashed
	}
	replacer := strings.NewReplacer("{EM}", msys(ext), "{EB}", filepath.FromSlash(ext), "{E}", filepath.ToSlash(ext),
		"{JM}", msys(junctions), "{J}", filepath.ToSlash(junctions), "{H}", filepath.ToSlash(home))
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if row.windowsOnly && runtime.GOOS != "windows" {
				t.Skip("a Windows spelling")
			}
			command := replacer.Replace(row.command)
			payload := mustJSON(t, map[string]any{"session_id": "disk-link-state", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": project, "tool_input": map[string]string{"command": command}})
			for _, withTargets := range []bool{true, false} {
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = "claudecode"
				store, logger := testStoreAndLogger(t)
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				if withTargets {
					if header := hookpaths.ResolveConnector("claudecode", "", "PreToolUse", payload); header != "" {
						req.Header.Set(hookpaths.Header, header)
					}
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
				got := recorder.Body.String()
				blocked := strings.Contains(got, `"action":"block"`)
				if row.rule == diskLinkUncertain {
					if blocked || !strings.HasPrefix(got, `{"action":"alert"`) || !strings.Contains(got, diskLinkKeysRule) {
						t.Fatalf("targets=%v %q: want an alert on the keys rule: %.400s", withTargets, command, got)
					}
					continue
				}
				if blocked != (row.rule != "") {
					t.Fatalf("targets=%v %q: block=%v, want %v: %.400s", withTargets, command, blocked, row.rule != "", got)
				}
				if row.rule == diskLinkAnyRule {
					if !strings.Contains(got, diskLinkStateRule) && !strings.Contains(got, diskLinkKeysRule) {
						t.Fatalf("targets=%v %q: blocked by another rule: %.400s", withTargets, command, got)
					}
				} else if row.rule != "" && !strings.Contains(got, row.rule) {
					t.Fatalf("targets=%v %q: blocked by another rule, want %s: %.400s", withTargets, command, row.rule, got)
				}
			}
		})
	}
}

// A write to the DefenseClaw config through an existing disk link (or
// junction) outside the home, direct or through a link the command makes,
// also inside bash -c or sh -c, is the state write the direct spelling is,
// and blocks as its ~/.ssh twin does (rel-1-0-6:GAP-0213). On Windows these
// writes were allowed while the keys twins blocked. Writes beside the link,
// reads through it and ordinary links stay allowed.
func TestClaudeBashWriteThroughDiskLinkToStateMatchesAcrossOS(t *testing.T) {
	judgeDiskLinkStateRows(t, []diskLinkStateRow{
		{name: "direct state write", command: `echo k >> ~/.defenseclaw/config.yaml`, rule: diskLinkStateRule},
		{name: "direct state write in bash -c", command: `bash -c "echo k >> ~/.defenseclaw/config.yaml"`, rule: diskLinkStateRule},
		{name: "through the disk link", command: `echo k >> {E}/y/config.yaml`, rule: diskLinkStateRule},
		{name: "through the disk link Git Bash drive", command: `echo k >> {EM}/y/config.yaml`, rule: diskLinkStateRule, windowsOnly: true},
		{name: "through the disk link backslashes", command: `echo k >> '{EB}\y\config.yaml'`, rule: diskLinkStateRule, windowsOnly: true},
		{name: "cd into the disk link", command: `cd {E}/y && echo k >> config.yaml`, rule: diskLinkStateRule},
		{name: "cd into the disk link Git Bash drive", command: `cd {EM}/y && echo k >> config.yaml`, rule: diskLinkStateRule, windowsOnly: true},
		{name: "through the disk link with tee", command: `echo k | tee -a {E}/y/config.yaml`, rule: diskLinkStateRule},
		{name: "cp through the disk link", command: `cp notes.txt {E}/y/config.yaml`, rule: diskLinkStateRule},
		{name: "through the disk link in bash -c", command: `bash -c "echo k >> {E}/y/config.yaml"`, rule: diskLinkStateRule},
		{name: "through the disk link in bash -c Git Bash drive", command: `bash -c "echo k >> {EM}/y/config.yaml"`, rule: diskLinkStateRule, windowsOnly: true},
		{name: "command link to the disk link", command: `ln -s {E}/y L && echo k >> L/config.yaml`, rule: diskLinkStateRule},
		{name: "command link to the disk link Git Bash drive", command: `ln -s {EM}/y L && echo k >> L/config.yaml`, rule: diskLinkStateRule, windowsOnly: true},
		{name: "command link then cd", command: `ln -s {E}/y L && cd L && echo k >> config.yaml`, rule: diskLinkStateRule},
		{name: "command link nested cd", command: `ln -s {E}/y L && (cd L && echo k >> config.yaml)`, rule: diskLinkStateRule},
		{name: "command link in bash -c", command: `bash -c "ln -s {E}/y L && echo k >> L/config.yaml"`, rule: diskLinkStateRule},
		{name: "command link in bash -c Git Bash drive", command: `bash -c "ln -s {EM}/y L && echo k >> L/config.yaml"`, rule: diskLinkStateRule, windowsOnly: true},
		{name: "command link in sh -c", command: `sh -c 'ln -s {E}/y L && echo k >> L/config.yaml'`, rule: diskLinkStateRule},
		{name: "command link in sh -c Git Bash drive", command: `sh -c 'ln -s {EM}/y L && echo k >> L/config.yaml'`, rule: diskLinkStateRule, windowsOnly: true},
		{name: "command link in bash -c then cd", command: `bash -c "ln -s {E}/y L && cd L && echo k >> config.yaml"`, rule: diskLinkUncertain},
		{name: "through the junction", command: `echo k >> {J}/y/config.yaml`, rule: diskLinkStateRule, windowsOnly: true},
		{name: "through the junction Git Bash drive", command: `echo k >> {JM}/y/config.yaml`, rule: diskLinkStateRule, windowsOnly: true},
		{name: "command link to the junction in bash -c", command: `bash -c "ln -s {JM}/y L && echo k >> L/config.yaml"`, rule: diskLinkStateRule, windowsOnly: true},
		{name: "keys twin through the disk link", command: `echo k >> {E}/x/authorized_keys`, rule: diskLinkKeysRule},
		{name: "keys twin through the disk link Git Bash drive", command: `echo k >> {EM}/x/authorized_keys`, rule: diskLinkKeysRule, windowsOnly: true},
		{name: "keys twin command link in bash -c", command: `bash -c "ln -s {EM}/x L && echo k >> L/authorized_keys"`, rule: diskLinkKeysRule, windowsOnly: true},
		{name: "keys twin command link in bash -c slash", command: `bash -c "ln -s {E}/x L && echo k >> L/authorized_keys"`, rule: diskLinkKeysRule},
		{name: "read through the disk link", command: `cat {E}/y/config.yaml`},
		{name: "list through the disk link", command: `ls {EM}/y`, windowsOnly: true},
		{name: "list through the disk link slash", command: `ls {E}/y`},
		{name: "write beside the disk links", command: `echo k >> {E}/notes.txt`},
		{name: "write to an ordinary folder outside", command: `echo k >> {EM}/ok/a.txt`, windowsOnly: true},
		{name: "write to an ordinary folder outside slash", command: `echo k >> {E}/ok/a.txt`},
		{name: "ordinary command link", command: `ln -s {E}/ok L2 && echo k >> L2/a.txt`},
		{name: "ordinary command link Git Bash drive", command: `ln -s {EM}/ok L2 && echo k >> L2/a.txt`, windowsOnly: true},
		{name: "ordinary command link in bash -c", command: `bash -c "ln -s {EM}/ok L2 && echo k >> L2/a.txt"`, windowsOnly: true},
		{name: "ordinary command link in bash -c slash", command: `bash -c "ln -s {E}/ok L2 && echo k >> L2/a.txt"`},
		{name: "ordinary write in bash -c", command: `bash -c "echo k >> notes.txt"`},
		{name: "plain project write", command: `echo k >> notes.txt`},
		{name: "remove the command link", command: `ln -s {E}/y L3 && rm L3`},
	})
}
