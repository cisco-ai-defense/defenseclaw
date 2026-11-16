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

// GAP-2569 (managed macOS) and GAP-2577 (managed Windows Git Bash): the
// GAP-2047 link-walk rows (rm -rf dclink/../.defenseclaw/*, git -C dclink
// clean -fdx) block on a per-user gateway, which walks the link itself, but
// a managed gateway judges a verified hook peer only from the hook client's
// evidence (it may not read the user's home: ProtectHome, another account).
// The client must therefore name the physical place of every directory a
// state-mutation operand walks through: the parent the kernel walks before
// a `..` after a link, a git -C or --work-tree directory and a cd target.
// Each row is sent through the hook endpoint as a managed peer with the
// client header, the home unreadable to the gateway.
func TestR105GAP2569ManagedLinkWalkUsesClientEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can search a mode 0 directory")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "home")
	home := filepath.Join(homes, "dcm-std1")
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, file := range []string{
		"config.yaml", "installer/install.sh", "hooks/claude-code-hook.sh",
		"policies/default.yaml", "logs/gateway.log",
	} {
		full := filepath.Join(state, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{".defenseclaw/installer", "build", "out", "proj2/build"} {
		if err := os.MkdirAll(filepath.Join(cwd, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"dclink": state, "hooklink": filepath.Join(state, "hooks")} {
		if err := os.Symlink(target, filepath.Join(cwd, link)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	send := func(t *testing.T, connector, mode, command string) string {
		t.Helper()
		if err := os.Chmod(homes, 0o700); err != nil {
			t.Fatal(err)
		}
		var payload []byte
		if connector == "codex" {
			payload = mustJSON(t, map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": cwd,
				"tool_name": "exec_command", "tool_use_id": "call_lw", "tool_input": map[string]any{"cmd": command}})
		} else {
			payload = mustJSON(t, map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": cwd,
				"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_lw",
				"tool_input": map[string]any{"command": command}})
		}
		header := hookpaths.ResolveConnector(connector, "", "PreToolUse", payload)
		// The managed gateway's view: it cannot search the user's home.
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
	blocked := []string{
		"rm -rf dclink/../.defenseclaw/*",
		"rm -rf dclink/../.defenseclaw/hooks",
		"rm -rf dclink/../.defenseclaw/hooks/",
		`rm -rf "dclink/../.defenseclaw/hooks"`,
		"rm -rf ~/project/dclink/../.defenseclaw/hooks",
		"rm -rf ./dclink/../.defenseclaw/installer",
		"find dclink/../.defenseclaw/hooks -delete",
		"mv dclink/../.defenseclaw/installer /tmp/i",
		"git -C dclink clean -fdx",
		"git -C hooklink clean -fdx",
		"git -C ~/project/dclink clean -fdx",
		"git -C ./dclink/ clean -fdX",
		"git --work-tree=hooklink clean -fdx",
		"git -C dclink reset --hard",
		"git -C dclink checkout -- .",
		"cd dclink && git clean -fdx",
		"cd hooklink && rm -rf ./*",
	}
	allowed := []string{
		"rm -rf dclink/../project/build",
		"rm -rf build/../out/*",
		"ls dclink/../",
		"cat dclink/../.defenseclaw/config.yaml",
		"git -C dclink status",
		"git -C dclink clean -n -d",
		"rm -f dclink/logs/gateway.log",
		"cd proj2 && git clean -fdx",
		"rsync -a dclink/ /tmp/dcbk/",
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, mode := range []string{"observe", "action"} {
			t.Run(connector+"/"+mode, func(t *testing.T) {
				for _, command := range blocked {
					got := send(t, connector, mode, command)
					if !strings.HasPrefix(got, `{"action":"block"`) || !strings.Contains(got, "tamper.detector_state_write") {
						t.Errorf("%s = %.400s, want block with tamper.detector_state_write", command, got)
					}
				}
				for _, command := range allowed {
					got := send(t, connector, mode, command)
					if strings.HasPrefix(got, `{"action":"block"`) || strings.Contains(got, "tamper.detector_state_write") {
						t.Errorf("%s = %.400s, want allow with no state finding", command, got)
					}
				}
			})
		}
	}
}
