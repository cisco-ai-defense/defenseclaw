// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestRelativeWriteTargetsInASandboxResolveInTheGuest pins that a relative
// write target of a sandboxed harness is judged where the guest writes it:
// against the guest's working directory, with the sandbox HOME as "~". The
// mount is the MicroVM layout (/sandbox/work/app) and the generic one
// (/work/app); a working directory with no mount (/sandbox) keeps its
// targets too. Native write tools and shell redirects of OpenCode, Copilot,
// Claude Code and Codex are covered. A project file named the same way
// stays allowed (GAP-0655).
func TestRelativeWriteTargetsInASandboxResolveInTheGuest(t *testing.T) {
	f := newSandboxIngressFixture(t)
	versions := map[string][3]string{
		"opencode":   {"2.1.4", "opencode-hooks-v2", "/api/v1/opencode/hook"},
		"copilot":    {"1.0.40", "copilot-hooks-v1", "/api/v1/copilot/hook"},
		"claudecode": {"2.1.156", "claudecode-hooks-v1", "/api/v1/claude-code/hook"},
		"codex":      {"0.128.0", "codex-hooks-v1", "/api/v1/codex/hook"},
	}
	opencodeEdit, copilotCreate := nativeWriteCalls()[0], nativeWriteCalls()[len(nativeWriteCalls())-1]
	if opencodeEdit.connector != "opencode" || opencodeEdit.tool != "edit" ||
		copilotCreate.connector != "copilot" || copilotCreate.tool != "create" {
		t.Fatal("nativeWriteCalls order changed")
	}
	opencodeBash := nativeWriteCall{"opencode", "shell", func(p string) map[string]any {
		return map[string]any{"command": "echo '# k' >> " + p}
	}}
	extraKeyEdit := nativeWriteExtraKeyCalls()[0]
	codexAddFile := nativeWriteCall{"codex", "apply_patch", func(p string) map[string]any {
		return map[string]any{"command": "*** Begin Patch\n*** Add File: " + p + "\n+# k\n*** End Patch\n"}
	}}
	shellRedirect := func(connector string) nativeWriteCall {
		return nativeWriteCall{connector, "Bash", func(p string) map[string]any {
			return map[string]any{"command": "echo '# k' >> " + p}
		}}
	}
	claudeWrite := nativeWriteCall{"claudecode", "Write", func(p string) map[string]any {
		return map[string]any{"file_path": p, "content": "# k\n"}
	}}
	for i, test := range []struct {
		call       nativeWriteCall
		mount, cwd string
		target     string
		want       bool
	}{
		{opencodeEdit, "/sandbox/work/app", "/sandbox/work/app", "../../.ssh/authorized_keys", true},
		{copilotCreate, "/sandbox/work/app", "/sandbox/work/app", "../../.ssh/authorized_keys", true},
		{extraKeyEdit, "/sandbox/work/app", "/sandbox/work/app", "../../.ssh/authorized_keys", true},
		{opencodeBash, "/sandbox/work/app", "/sandbox/work/app", "../../.ssh/authorized_keys", true},
		{opencodeEdit, "/work/app", "/work/app", "../../sandbox/.ssh/authorized_keys", true},
		{opencodeEdit, "/work/app", "/sandbox", ".ssh/authorized_keys", true},
		{copilotCreate, "/work/app", "/sandbox", ".ssh/authorized_keys", true},
		{opencodeBash, "/work/app", "/sandbox", ".ssh/authorized_keys", true},
		{codexAddFile, "/sandbox/work/app", "/sandbox/work/app", "../../.ssh/authorized_keys", true},
		{shellRedirect("codex"), "/sandbox/work/app", "/sandbox/work/app", "../../.ssh/authorized_keys", true},
		{shellRedirect("claudecode"), "/sandbox/work/app", "/sandbox/work/app", "../../.ssh/authorized_keys", true},
		{shellRedirect("claudecode"), "/work/app", "/sandbox", ".ssh/authorized_keys", true},
		{claudeWrite, "/work/app", "/sandbox", ".ssh/authorized_keys", true},
		{opencodeEdit, "/sandbox/work/app", "/sandbox/work/app", "notes.txt", false},
		{codexAddFile, "/sandbox/work/app", "/sandbox/work/app", "notes.txt", false},
		{shellRedirect("codex"), "/sandbox/work/app", "/sandbox/work/app", "notes.txt", false},
		{shellRedirect("claudecode"), "/sandbox/work/app", "/sandbox/work/app", "notes.txt", false},
		{copilotCreate, "/sandbox/work/app", "/sandbox/work/app", "docs/notes.txt", false},
		{extraKeyEdit, "/sandbox/work/app", "/sandbox/work/app", "notes.txt", false},
		{opencodeBash, "/sandbox/work/app", "/sandbox/work/app", "notes.txt", false},
		{opencodeEdit, "/work/app", "/sandbox", ".ssh/config.sample", false},
	} {
		name := fmt.Sprintf("%d-%s-%s-%s-block=%t", i, test.call.connector, test.call.tool, test.cwd, test.want)
		t.Run(name, func(t *testing.T) {
			v := versions[test.call.connector]
			_, token, err := f.store.Mint(sandboxauth.Spec{
				SandboxName: fmt.Sprintf("dc-rel-%d", i), Connector: test.call.connector, AgentVersion: v[0],
				HookContractID: v[1], PolicyProfile: "open", HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
				Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirMount,
					Mounts: []sandboxauth.Mount{{SandboxPath: test.mount, HostPath: f.project}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			var headers []string
			switch test.call.connector {
			case "copilot":
				headers = []string{"X-DefenseClaw-Copilot-Event", "preToolUse"}
			case "codex":
				headers = []string{"X-DefenseClaw-Hook-Event", "PreToolUse", "X-DefenseClaw-Hook-Contract", v[1]}
			}
			resp := f.hook(t, v[2], token, test.call.body(t, test.cwd, test.target), headers...)
			raw, _ := json.Marshal(resp)
			if got := nativeWriteBlocked(t, string(raw)); got != test.want {
				t.Fatalf("blocked = %t, want %t: %.600s", got, test.want, raw)
			}
		})
	}
}
