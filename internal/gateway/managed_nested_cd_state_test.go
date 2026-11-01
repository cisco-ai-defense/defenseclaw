// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-2485 (T11 IVS, managed AD RHEL): a managed gateway behind ProtectHome
// gets no cwd of its own for a verified hook peer, so the cd walk of a
// relative state pattern (`sh -c "cd a; cd b; cd c; cd d; rm -rf
// ../../../../.defenseclaw/hooks/*"`) started nowhere and proved nothing;
// the per-user gateway blocks the same rows. The call must be walked from
// the client cwd, for any legal home spelling (an AD home has an @).
func TestR105GAP2485ManagedCdWalkUsesClientCWD(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can search a mode 0 directory")
	}
	for _, user := range []string{"dcm-std1", "dcad-eng1@dclab.test", "dc user+1"} {
		t.Run(user, func(t *testing.T) {
			root := t.TempDir()
			homes := filepath.Join(root, "home")
			home := filepath.Join(homes, user)
			state := filepath.Join(home, ".defenseclaw")
			for _, file := range []string{"config.yaml", "installer/install.sh", "hooks/claude-code-hook.sh", "logs/gateway.log"} {
				full := filepath.Join(state, filepath.FromSlash(file))
				if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte("fixture\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, dir := range []string{"a/b/c/d/e", "proj2/build/x/y"} {
				if err := os.MkdirAll(filepath.Join(home, filepath.FromSlash(dir)), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
			send := func(t *testing.T, connector, mode, cwd, command string) string {
				t.Helper()
				if err := os.Chmod(homes, 0o700); err != nil {
					t.Fatal(err)
				}
				var payload []byte
				if connector == "codex" {
					payload = mustJSON(t, map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": cwd,
						"tool_name": "exec_command", "tool_use_id": "call_cd", "tool_input": map[string]any{"cmd": command}})
				} else {
					payload = mustJSON(t, map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": cwd,
						"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_cd",
						"tool_input": map[string]any{"command": command}})
				}
				header := hookpaths.ResolveConnector(connector, "", "PreToolUse", payload)
				if err := os.Chmod(homes, 0); err != nil {
					t.Fatal(err)
				}
				cfg := &config.Config{}
				cfg.Guardrail.Mode = mode
				cfg.Guardrail.Connector = connector
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
				req.Header.Set(hookpaths.Header, header)
				if connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
				recorder := httptest.NewRecorder()
				api.handleAgentHook(connector).ServeHTTP(recorder, req)
				return recorder.Body.String()
			}
			project := filepath.Join(home, "proj2")
			type row struct {
				cwd, command string
				block        bool
			}
			rows := []row{
				{home, "sh -c \"cd a; cd b; cd c; cd d; cd ../../../../.defenseclaw; rm -rf hooks/*\"", true},
				{home, "sh -c \"cd a; cd b; cd c; cd d; rm -rf ../../../../.defenseclaw/hooks/*\"", true},
				{home, "cd a; cd b; cd c; cd d; cd e; rm -rf ../../../../../.defenseclaw/hooks/*", true},
				{home, "sh -c \"cd .defenseclaw; rm -rf hooks/*\"", true},
				{home, "sh -c \"pushd a; cd b; cd c; cd d; cd e; popd; rm -rf .defenseclaw/hooks/*\"", true},
				{project, "sh -c \"cd ..; rm -rf .defenseclaw/hooks/*\"", true},
				{project, "cd ../.defenseclaw && sort -o config.yaml /tmp/x", true},
				// Allowed and quiet.
				{home, "sh -c \"cd proj2; cd build; cd x; cd y; rm -rf ../../*.o\"", false},
				{home, "sh -c \"cd proj2; rm -rf build/*\"", false},
				{home, "sh -c \"cd .defenseclaw/logs; rm -f *.log\"", false},
				{project, "cd build && rm -rf ./*", false},
				{project, "ls -la ../.defenseclaw", false},
			}
			for _, connector := range []string{"claudecode", "codex"} {
				for _, mode := range []string{"observe", "action"} {
					for _, r := range rows {
						got := send(t, connector, mode, r.cwd, r.command)
						// Observe reports the finding; action blocks.
						if r.block && (mode == "action" && !strings.HasPrefix(got, `{"action":"block"`) || !strings.Contains(got, "tamper.detector_state_write")) {
							t.Errorf("%s/%s %s = %.400s, want the tamper.detector_state_write finding (block in action)", connector, mode, r.command, got)
						}
						if !r.block && (strings.HasPrefix(got, `{"action":"block"`) || strings.Contains(got, "tamper.detector_state_write")) {
							t.Errorf("%s/%s %s = %.400s, want allow with no state finding", connector, mode, r.command, got)
						}
					}
				}
			}
		})
	}
}
