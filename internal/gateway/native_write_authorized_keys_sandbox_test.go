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

// TestNativeWriteToolsOfAuthorizedKeysAreBlockedInASandbox is the same
// table for a sandboxed harness, through the authenticated sandbox ingress:
// the guest home is the sandbox HOME, so the protected file is
// /sandbox/.ssh/authorized_keys, and a file of the mounted project stays
// allowed.
func TestNativeWriteToolsOfAuthorizedKeysAreBlockedInASandbox(t *testing.T) {
	f := newSandboxIngressFixture(t)
	versions := map[string][3]string{
		"opencode":   {"2.1.4", "opencode-hooks-v2", "/api/v1/opencode/hook"},
		"claudecode": {"2.1.156", "claudecode-hooks-v1", "/api/v1/claude-code/hook"},
		"codex":      {"0.128.0", "codex-hooks-v1", "/api/v1/codex/hook"},
		"copilot":    {"1.0.40", "copilot-hooks-v1", "/api/v1/copilot/hook"},
	}
	keys := sandboxauth.SandboxHome + "/.ssh/authorized_keys"
	for i, call := range nativeWriteTableCalls() {
		v := versions[call.connector]
		var headers []string
		switch call.connector {
		case "codex":
			headers = []string{"X-DefenseClaw-Hook-Event", "PreToolUse", "X-DefenseClaw-Hook-Contract", v[1]}
		case "copilot":
			headers = []string{"X-DefenseClaw-Copilot-Event", "preToolUse"}
		}
		for target, want := range map[string]bool{keys: true, "/work/app/notes.txt": false} {
			t.Run(fmt.Sprintf("%s/block=%t", call.name(i), want), func(t *testing.T) {
				_, token := f.mint(t, fmt.Sprintf("dc-%s-%t", call.name(i), want), call.connector, v[0], v[1], f.project)
				resp := f.hook(t, v[2], token, call.body(t, "/work/app", target), headers...)
				raw, _ := json.Marshal(resp)
				if got := nativeWriteBlocked(t, string(raw)); got != want {
					t.Fatalf("blocked = %t, want %t: %.600s", got, want, raw)
				}
			})
		}
	}
}
