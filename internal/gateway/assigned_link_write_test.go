// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// perUserLinkHook sends body to a per-user gateway (no managed peer), as an
// OSS install runs the hook.
func perUserLinkHook(t *testing.T, connector, body string) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(connector, "", "preToolUse", []byte(body)))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	return recorder.Body.String()
}

// GAP-2514 (GitHub #1168 forms 3 and 4) and GAP-2515 (GitHub #1170 form 2):
// a write target named by a shell variable assigned in the same command, a
// ${f:-default} default, or a tar -C directory that is a link into ~/.ssh,
// reaching ~/.ssh/authorized_keys, is a key write on a managed gateway
// (ProtectHome, client walk) and on a per-user gateway alike. The same
// shapes writing ordinary project files stay allowed.
func TestAssignedAndTarDirectoryWritesThroughLinks(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	project := filepath.Join(home, "t9proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "out")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, file := range []string{keys, filepath.Join(project, "notes.txt")} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, name := range []string{"authorized_keys", "notes.txt"} {
		content := []byte("# member\n")
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "keys.tar"), archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct{ name, target string }{
		{filepath.Join(project, "disklink"), filepath.FromSlash("../.ssh/authorized_keys")},
		{filepath.Join(project, "dirlink"), filepath.FromSlash("../.ssh")},
	} {
		if err := os.Symlink(link.target, link.name); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	cases := []struct {
		command string
		block   bool
	}{
		{`tee -a disklink < notes.txt`, true},
		{`f=disklink; printf '# reviewed\n' | tee -a "$f"`, true},
		{`f=disklink; printf '# reviewed\n' | tee "$f" > /dev/null`, true},
		{`f=disklink && echo '# reviewed' >> "$f"`, true},
		{`f=disklink; echo '# reviewed' >> $f`, true},
		{`echo '# reviewed' >> ${f:-disklink}`, true},
		{`echo '# reviewed' >> "${f-disklink}"`, true},
		{`printf '# reviewed\n' | tee -a ${f:-disklink}`, true},
		{`tar -C dirlink -xf keys.tar authorized_keys`, true},
		{`tar -xf keys.tar -C dirlink authorized_keys`, true},
		{`tar xf keys.tar -C dirlink`, true},
		{`tar --directory=dirlink -xf keys.tar`, true},
		{`f=notes.txt; printf '# reviewed\n' | tee -a "$f"`, false},
		{`f=notes.txt && echo '# reviewed' >> "$f"`, false},
		{`echo '# reviewed' >> ${f:-notes.txt}`, false},
		{`printf '# reviewed\n' | tee -a ${f:-notes.txt}`, false},
		{`tar -C out -xf keys.tar authorized_keys`, false},
		{`tar -xf keys.tar -C out`, false},
		{`tar -C out -cf ../bundle.tar .`, false},
	}
	for _, managed := range []bool{true, false} {
		for _, connector := range []string{"claudecode", "codex"} {
			for _, tc := range cases {
				name := "per-user"
				if managed {
					name = "managed"
				}
				t.Run(name+"/"+connector+"/"+tc.command, func(t *testing.T) {
					if err := os.Chmod(homes, 0o700); err != nil {
						t.Fatal(err)
					}
					event := map[string]any{"session_id": "gap2514", "hook_event_name": "PreToolUse",
						"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": tc.command}}
					if connector == "codex" {
						event["turn_id"], event["tool_use_id"] = "t1", "tu-gap2514"
					}
					body, err := json.Marshal(event)
					if err != nil {
						t.Fatal(err)
					}
					var got string
					if managed {
						evidence := hookpaths.Resolve(body)
						if err := os.Chmod(homes, 0); err != nil {
							t.Fatal(err)
						}
						got = overLimitHostHookWithEvidence(t, connector, home, string(body), evidence)
					} else {
						got = perUserLinkHook(t, connector, string(body))
					}
					if blocked := nativeWriteBlocked(t, got); blocked != tc.block {
						t.Fatalf("blocked = %t, want %t: %.600s", blocked, tc.block, got)
					}
				})
			}
		}
	}
}
