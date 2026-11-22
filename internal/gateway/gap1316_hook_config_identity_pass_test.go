// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The hook-config guard reads the identity of each file once in a pass over
// targets, and a pass never answers from the reads of another
// (rel-1-0-10:GAP-1316). A target that is a hard link of the Claude Code
// settings file is a settings file. Within one pass it stays one after the
// link is broken (the pass read it once); the next pass reads it again and
// finds an ordinary file. A guard between passes keeps no identities.
func TestGAP1316HookConfigIdentityReadsLastOnePass(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, "notes.txt")
	if err := os.Link(settings, alias); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	guard := newAgentHookConfigGuard(home, home)
	if got := guard.format(alias); got != gatewayconnector.AgentHookConfigClaudeSettings {
		t.Fatalf("format of the settings hard link = %q, want %q", got, gatewayconnector.AgentHookConfigClaudeSettings)
	}
	if guard.identities != nil {
		t.Fatal("format left its pass open")
	}

	began := guard.beginIdentityPass()
	if !began || guard.beginIdentityPass() {
		t.Fatal("a pass did not begin once")
	}
	if got := guard.format(alias); got != gatewayconnector.AgentHookConfigClaudeSettings {
		t.Fatalf("format in the pass = %q, want the settings format", got)
	}
	if guard.identities == nil {
		t.Fatal("format in a pass ended the lane's pass")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alias, []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := guard.format(alias); got != gatewayconnector.AgentHookConfigClaudeSettings {
		t.Fatalf("format later in the same pass = %q, want the pass's first answer", got)
	}
	guard.endIdentityPass(began)
	if guard.identities != nil {
		t.Fatal("the pass kept its identities after its end")
	}
	if got := guard.format(alias); got != "" {
		t.Fatalf("format in the next pass = %q, want an ordinary file", got)
	}
}
