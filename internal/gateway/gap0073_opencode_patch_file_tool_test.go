// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// POSIX permissions emulate the managed gateway that cannot read the
// user project.

//go:build !windows

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

// opencodeV2PatchBody is the managed OpenCode 2.2.5 tool.execute.before body
// of its native patch tool, field for field as captured on a managed host.
func opencodeV2PatchBody(t *testing.T, cwd, tool, patch string) string {
	t.Helper()
	return string(mustJSON(t, map[string]any{"hook_event_name": "tool.execute.before", "tool_name": tool,
		"tool_input": map[string]any{"patchText": patch}, "session_id": "session-gap0073", "turn_id": "message-1",
		"tool_call_id": "call-1", "agent_name": "build", "cwd": cwd, "load_heartbeat": true,
		"arguments_authoritative": true, "mcp_identity_status": "not_mcp"}))
}

// managedOpenCodeHook judges one OpenCode hook call as a managed gateway that
// cannot read the user home (ProtectHome), with the evidence header the hook
// client computes as the user before the home is locked.
func managedOpenCodeHook(t *testing.T, home, pack, body string) hermesHookOutcome {
	t.Helper()
	header := hookpaths.ResolveConnector("opencode", "", "tool.execute.before", []byte(body))
	root := filepath.Dir(home)
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(root, 0o700)
	if _, err := os.ReadDir(home); err == nil {
		t.Skip("the test process can read a locked directory")
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "opencode"
	cfg.Guardrail.RulePack = pack
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/opencode/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, header)
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	out := httptest.NewRecorder()
	api.handleAgentHook("opencode").ServeHTTP(out, req)
	return hermesOutcome(t, out.Body.String())
}

// GAP-0073: OpenCode V2 native patch tool ("patch", patchText) is a file
// tool. The hook client describes it under the apply_patch name the gateway
// judges it as, so a managed gateway that cannot read the project allows a
// patch that creates, edits or moves an ordinary file in every profile, as
// it allows the apply_patch spelling, and a patch whose target is the key
// file, named directly or through a link, stays blocked.
func TestGAP0073ManagedOpenCodePatchIsAFileTool(t *testing.T) {
	home, project := hermesPatchHome(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	envelope := func(body string) string { return "*** Begin Patch\n" + body + "*** End Patch" }
	ordinary := map[string]string{
		"add":          envelope("*** Add File: hello.txt\n+hello\n"),
		"add-absolute": envelope("*** Add File: " + filepath.Join(project, "abs.txt") + "\n+hello\n"),
		"update":       envelope("*** Update File: notes.txt\n@@\n # base\n+# k\n"),
		"move":         envelope("*** Update File: notes.txt\n*** Move to: moved.txt\n@@\n # base\n+# k\n"),
		"delete":       envelope("*** Delete File: notes.txt\n"),
	}
	protected := map[string]string{
		"add-keys":     envelope("*** Add File: " + keys + "\n+k\n"),
		"update-keys":  envelope("*** Update File: " + keys + "\n@@\n # base\n+# k\n"),
		"update-link":  envelope("*** Update File: keylink\n@@\n # base\n+# k\n"),
		"move-to-keys": envelope("*** Update File: notes.txt\n*** Move to: " + keys + "\n@@\n # base\n+# k\n"),
		"ordinary+link": envelope("*** Add File: hello.txt\n+hello\n" +
			"*** Update File: keylink\n@@\n # base\n+# k\n"),
	}
	for _, tool := range []string{"patch", "apply_patch"} {
		for _, pack := range []string{"", "strict"} {
			for name, patch := range ordinary {
				got := managedOpenCodeHook(t, home, pack, opencodeV2PatchBody(t, project, tool, patch))
				if got.action != "allow" {
					t.Errorf("%s pack %q %s: %s, want allow", tool, pack, name, got)
				}
			}
			for name, patch := range protected {
				got := managedOpenCodeHook(t, home, pack, opencodeV2PatchBody(t, project, tool, patch))
				if got.action != "block" || !got.rules[nativeWriteAuthorizedKeysRule] {
					t.Errorf("%s pack %q %s: %s, want block by %s", tool, pack, name, got, nativeWriteAuthorizedKeysRule)
				}
			}
		}
	}
}
