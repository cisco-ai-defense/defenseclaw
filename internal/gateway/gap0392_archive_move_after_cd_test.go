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
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-0392: a placed cd does not turn an absolute archive extraction and
// safe rename into an unbounded link write. A later ordinary write into the
// archive scope follows the balanced policy decision.
func TestGAP0392ArchiveMoveAfterCdFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	clean := filepath.Join(f.home, "clean")
	if err := os.MkdirAll(clean, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clean, "out.tgz"), []byte("fixture archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command, want string }{
		{"and-cd", `cd ~/clean && tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo done`, "allow"},
		{"semicolon-cd", `cd ~/clean; tar -xzf out.tgz -C /tmp; mv /tmp/src /tmp/src-old; echo done`, "allow"},
		{"redirected-cd", `cd ~/clean && tar -xzf out.tgz -C /tmp 2>/dev/null; mv /tmp/src /tmp/src-old 2>/dev/null; echo done`, "allow"},
		{"no-cd-control", `tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo done`, "allow"},
		{"scope-write-after-rename", `cd ~/clean && tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo x >> /tmp/src-old/authorized_keys`, "alert"},
		{"keys-link-write-after-rename", `cd ~/clean && tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo x >> ~/clean/keylink`, "block"},
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(clean, "keylink")); err != nil {
		t.Fatal(err)
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, mustJSON(t, map[string]any{"session_id": "b36", "hook_event_name": "PreToolUse", "cwd": clean,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_b36",
			"tool_input": map[string]any{"command": row.command, "description": "Run test fixture command"}}))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode("GAP0392/"+row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		if want == "alert" {
			if !strings.HasPrefix(call.body, `{"action":"alert"`) {
				t.Errorf("%s: body %.200s, want a visible allow warning", call.name, call.body)
			}
			continue
		}
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			got := gx054Verdict(t, f, connector, "strict", payloads[4], headers[4], managed)
			if got == "allow" {
				t.Errorf("%s managed=%t: strict permitted ordinary archive scope write", connector, managed)
			}
		}
	}

}

// GAP-0627: a variable extraction directory carries only an unverified
// archive scope. The ordinary packaging chain is allowed in balanced and
// remains a strict finding, including for the managed Codex hook.
func TestGAP0627VariablePackagingChainFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	t.Setenv("TMPDIR", filepath.Join(f.home, "tmp"))
	clean := filepath.Join(f.home, "clean")
	for _, dir := range []string{clean, filepath.Join(f.home, "tmp")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(clean, "out.tgz"), []byte("fixture archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`cd ~/clean && tar -xzf out.tgz -C $TMPDIR && mv $TMPDIR/src $TMPDIR/src-old && echo done`,
		`cd ~/clean; tar -xzf out.tgz -C $TMPDIR; mv $TMPDIR/src $TMPDIR/src-old; echo done`,
		`cd ~/clean && tar -xzf out.tgz -C $TMPDIR 2>/dev/null; mv $TMPDIR/src $TMPDIR/src-old 2>/dev/null; echo done`,
		`cd ~/clean && tar -xzf out.tgz -C $HOME/tmp && mv $HOME/tmp/src $HOME/tmp/src-old && echo done`,
		`cd ~/clean && tar -xzf out.tgz -C $TMPDIR && echo done > build-note.txt`,
	} {
		payload := mustJSON(t, map[string]any{"session_id": "gap0627", "hook_event_name": "PreToolUse", "cwd": clean,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "gap0627",
			"tool_input": map[string]any{"command": command, "description": "Package fixture"}})
		header := f.clientHeaders(t, [][]byte{payload})[0]
		for _, connector := range []string{"claudecode", "codex"} {
			for _, managed := range []bool{false, true} {
				if got := gx054Verdict(t, f, connector, "", payload, header, managed); got != "allow" {
					t.Errorf("%s managed=%t command=%q balanced=%s", connector, managed, command, got)
				}
				strict := gx054Verdict(t, f, connector, "strict", payload, header, managed)
				if strict == "allow" {
					t.Errorf("%s managed=%t command=%q strict=%s, want block", connector, managed, command, strict)
				}
			}
		}
	}
}

// GAP-0631: an archive extracted outside the later write's path cannot
// create that write target. Keep the original GAP-0392 replay shapes beside
// the disjoint and overlapping path controls.
func TestGAP0631DisjointArchiveWriteFourCell(t *testing.T) {
	if info, err := os.Stat("/var/tmp"); err != nil || !info.IsDir() {
		t.Skip("separate temporary root unavailable")
	}
	t.Setenv("TMPDIR", "/var/tmp")
	f := newB36ManagedHookFixture(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	clean := filepath.Join(f.home, "clean")
	extract := filepath.Join(f.home, "extract")
	ownTmp, err := os.MkdirTemp("/tmp", "gx054-r3-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(ownTmp) })
	for _, dir := range []string{clean, extract, filepath.Join(extract, "nested")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(clean, "out.tgz"), []byte("unread archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		strictBlock   bool
	}{
		{"V5-live", "tar -xzf out.tgz -C /tmp && echo done > build-note.txt", false},
		{"V5", "tar -xzf out.tgz -C " + extract + " && echo done > build-note.txt", false},
		{"V5-cd", "cd " + clean + " && tar -xzf out.tgz -C " + extract + " && echo done > build-note.txt", false},
		{"V5-dot", "tar -xzf out.tgz -C " + extract + "/. && echo done > ./build-note.txt", false},
		{"V5-parent", "tar -xzf out.tgz -C " + extract + "/nested/.. && echo done > build-note.txt", false},
		{"V5-home", "tar -xzf out.tgz -C ~/extract && echo done > ~/clean/build-note.txt", false},
		{"overlap", "tar -xzf out.tgz -C " + extract + " && echo done > " + extract + "/note.txt", true},
		{"nested", "tar -xzf out.tgz -C " + extract + " && echo done > " + extract + "/nested/note.txt", true},
		{"overlap-dot", "tar -xzf out.tgz -C " + extract + "/. && echo done > " + extract + "/./note.txt", true},
		{"overlap-parent", "tar -xzf out.tgz -C " + extract + "/nested/.. && echo done > " + extract + "/note.txt", true},
		{"overlap-home", "tar -xzf out.tgz -C ~/extract && echo done > ~/extract/note.txt", true},
		{"W1", "cd ~/clean && tar -xzf out.tgz -C " + ownTmp + " 2>/dev/null; mv " + ownTmp + "/src " + ownTmp + "/src-old 2>/dev/null; echo done", false},
		{"W2", "cd ~/clean && tar -xzf out.tgz -C " + ownTmp + "; mv " + ownTmp + "/src " + ownTmp + "/src-old; echo done", false},
		{"W3", "cd ~/clean && tar -xzf out.tgz -C " + ownTmp + " 2>/dev/null; echo done", false},
		{"W4", "cd ~/clean && tar -xzf out.tgz -C " + ownTmp + " && mv " + ownTmp + "/src " + ownTmp + "/src-old && echo done", false},
		{"W5", "tar -xzf out.tgz -C " + ownTmp + " 2>/dev/null; mv " + ownTmp + "/src " + ownTmp + "/src-old 2>/dev/null; echo done", false},
		{"W6", "cd ~/clean && tar -xzf out.tgz -C " + ownTmp + " 2>/dev/null; mv " + ownTmp + "/src " + ownTmp + "/src-old; echo done", false},
		{"V1", "tar -xzf out.tgz -C " + ownTmp + " 2>/dev/null; echo done", false},
		{"V2", "tar -xzf out.tgz -C " + ownTmp + "; mv " + ownTmp + "/src " + ownTmp + "/src-old 2>/dev/null; echo done", false},
		{"V3", "tar -xzf out.tgz -C " + ownTmp + " && echo done > /dev/null", false},
		{"V4", "tar -xzf out.tgz -C " + ownTmp + " && mv " + ownTmp + "/src " + ownTmp + "/src-old && echo done", false},
		{"V6", "tar -xzf out.tgz -C " + ownTmp + " 2> err.log; echo done", false},
		{"T1", "cd ~/clean && tar -xzf out.tgz -C " + ownTmp + " && mv " + ownTmp + "/src " + ownTmp + "/src-old && echo done", false},
		{"T2", "cd ~/clean && tar -xzf out.tgz -C " + ownTmp + "; mv " + ownTmp + "/src " + ownTmp + "/src-old; echo done", false},
		{"T3", "cd ~/clean && tar -xzf out.tgz -C " + ownTmp + " 2>/dev/null; mv " + ownTmp + "/src " + ownTmp + "/src-old 2>/dev/null; echo done", false},
		{"T4", "tar -xzf out.tgz -C " + ownTmp + " && mv " + ownTmp + "/src " + ownTmp + "/src-old && echo done", false},
		{"T5", "tar -xzf out.tgz -C " + ownTmp + "; mv " + ownTmp + "/src " + ownTmp + "/src-old; echo done", false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			payload := mustJSON(t, map[string]any{"session_id": "gap0631", "hook_event_name": "PreToolUse", "cwd": clean, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "gap0631", "tool_input": map[string]any{"command": row.command, "description": "Package fixture"}})
			header := f.clientHeaders(t, [][]byte{payload})[0]
			for _, connector := range []string{"claudecode", "codex"} {
				for _, managed := range []bool{false, true} {
					for _, tier := range []string{"", "strict"} {
						got := gx054Verdict(t, f, connector, tier, payload, header, managed)
						wantBlock := row.strictBlock && tier == "strict"
						if (got != "allow") != wantBlock {
							t.Errorf("%s managed=%t tier=%q: got %s, want block=%t", connector, managed, tier, got, wantBlock)
						}
					}
				}
			}
		})
	}
	// An overlapping unread scope is a visible Possible finding in balanced.
	row := rows[6]
	payload := mustJSON(t, map[string]any{"session_id": "gap0631-warning", "hook_event_name": "PreToolUse", "cwd": clean, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "gap0631-warning", "tool_input": map[string]any{"command": row.command, "description": "Package fixture"}})
	header := f.clientHeaders(t, [][]byte{payload})[0]
	for _, connector := range []string{"claudecode", "codex"} {
		cfg := &config.Config{}
		cfg.Guardrail.Mode, cfg.Guardrail.Connector = "action", connector
		cfg.DataDir = os.Getenv("DEFENSECLAW_HOME")
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(hookpaths.Header, header)
		if connector == "codex" {
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
		}
		rec := httptest.NewRecorder()
		api.handleAgentHook(connector).ServeHTTP(rec, req)
		if !strings.Contains(rec.Body.String(), "Archive extraction has an unverified link scope for a later write") {
			t.Errorf("%s balanced Possible warning missing: %.300s", connector, rec.Body.String())
		}
	}
}
