// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

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
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap0270Hook sends one Bash PreToolUse call to a per-user gateway in
// action mode, with the hook client's evidence header, and returns the
// answer.
func gap0270Hook(t *testing.T, connector, cwd, command string, strict bool) string {
	t.Helper()
	body := mustJSON(t, map[string]any{"session_id": "gap0270", "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "cwd": cwd, "tool_input": map[string]any{"command": command, "description": "d"}})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	if strict {
		cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	}
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
	req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	return recorder.Body.String()
}

func gap0270Fill(t *testing.T, dir string, n int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(entries); i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("fill-%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// rel-1-0-10:GAP-0270: the corpus shapes over a temp folder get the same
// answer whether the folder holds a few names or more than the pattern walk
// reads (4096). On dc-build-1 (/tmp 17,212 entries) the for-loop and
// redirect shapes were CRITICAL persistence.ssh_authorized_keys_command
// blocks, on dc-s7-bench (/tmp 468 entries) allows.
func TestGAP0270GatewayBusyTempFolderSameAnswer(t *testing.T) {
	root := t.TempDir()
	home, busy := filepath.Join(root, "home"), filepath.Join(root, "tmp")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project, busy} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rows := []string{
		"ls " + busy + "/x-*.log 2>/dev/null",
		"du -sh " + busy + "/x-* 2>/dev/null",
		"for f in " + busy + "/x-*.log; do echo \"$f\"; done",
		"cat " + busy + "/x-*.log > out.txt",
	}
	for _, size := range []int{0, 4097} {
		gap0270Fill(t, busy, size)
		for _, connector := range []string{"claudecode", "codex"} {
			for _, command := range rows {
				t.Run(fmt.Sprintf("%s/%d/%s", connector, size, strings.ReplaceAll(command, busy, "BUSY")), func(t *testing.T) {
					if got := gap0270Hook(t, connector, project, command, false); !strings.HasPrefix(got, `{"action":"allow"`) {
						t.Fatalf("answer = %.500s, want allow", got)
					}
				})
			}
		}
	}
}

// rel-1-0-10:GAP-0270 (b), GAP-0401: a pattern under the home whose walk
// passes its bound (lowered here) and finds no alias is TRUNCATED through
// internal/guardrail/bounded: the evaluation-limit finding names the cap,
// the default pack alerts and the strict pack blocks, never a proved
// authorized-keys write.
func TestGAP0270GatewayInHomeBoundNamedUnknown(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "build")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	defer hookpaths.UseGlobWalkBoundsForTests(64, 64)()
	const command = "cp payload b*/"
	if got := gap0270Hook(t, "claudecode", project, command, false); !strings.HasPrefix(got, `{"action":"allow"`) {
		t.Fatalf("small folder answer = %.500s, want allow", got)
	}
	gap0270Fill(t, project, 200)
	reason := bounded.Of(bounded.Items).Reason()
	for _, strict := range []bool{false, true} {
		got := gap0270Hook(t, "claudecode", project, command, strict)
		t.Logf("strict=%t busy: %.900s", strict, got)
		if !strings.Contains(got, reason) {
			t.Fatalf("strict=%t busy folder answer = %.700s, want the truncation reason %q", strict, got, reason)
		}
		if blocked := strings.HasPrefix(got, `{"action":"block"`); blocked != strict {
			t.Fatalf("strict=%t busy folder answer = %.700s, want block only in strict", strict, got)
		}
		if strings.Contains(got, "persistence.ssh_authorized_keys_command") && !strict {
			t.Fatalf("default busy folder answer = %.700s, names a key write", got)
		}
	}
}

// rel-1-0-10:GAP-0441 (review round 2 probe G6): at the gateway, a write
// through the GAP-0270 shape S7's x-*/*.txt over an away folder of
// subfolders, one of which holds a link of an ordinary name to
// authorized_keys. The link takes every position. With the read bound
// lowered, a link the walk read is a CRITICAL authorized-keys block in
// default and strict; one it did not read is TRUNCATED (the evaluation-limit
// finding names cap paths): the default pack alerts and the strict pack
// blocks. No position is a plain allow.
func TestGAP0441GatewayUnreadLinkIsTruncated(t *testing.T) {
	const subfolders, reads = 8, 4
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	away := filepath.Join(root, "tmp")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project, away} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "payload")} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for k := range subfolders {
		if err := os.Mkdir(filepath.Join(away, fmt.Sprintf("x-%02d", k)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	defer hookpaths.UseGlobWalkBoundsForTests(reads, 1<<18)()
	pattern := away + "/x-*/*.txt"
	rows := []string{"cp payload " + pattern, "tee " + pattern + " < payload"}
	reason := bounded.Of(bounded.Paths).Reason()
	held := 0
	for k := range subfolders {
		link := filepath.Join(away, fmt.Sprintf("x-%02d", k), "n.txt")
		if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), link); err != nil {
			t.Fatal(err)
		}
		for i, command := range rows {
			for _, strict := range []bool{false, true} {
				got := gap0270Hook(t, "claudecode", project, command, strict)
				blocked := strings.HasPrefix(got, `{"action":"block"`)
				keyWrite := strings.Contains(got, "persistence.ssh_authorized_keys_command")
				truncated := strings.Contains(got, reason)
				switch {
				case blocked && keyWrite && strings.Contains(got, "CRITICAL"):
				case truncated && blocked == strict:
					held++
				default:
					t.Errorf("row %d, link in subfolder %d, strict=%t: answer %.700s, want a CRITICAL key-write block or TRUNCATED", i, k, strict, got)
				}
			}
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}
	if held == 0 {
		t.Fatal("no position was past the lowered read bound")
	}
}
