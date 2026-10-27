// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestStaleTeardownKeepsTheNewerRegistrationsCredential is GAP-1728: a
// teardown revokes the credential of the registration it removes. A stale
// teardown that runs after the connector was set up again (with a newly
// issued credential) keeps that newer credential, so the authenticated
// SessionStart that recovers the registration is not refused with 401. A
// teardown of the current registration, or one that names no credential,
// still revokes it.
func TestStaleTeardownKeepsTheNewerRegistrationsCredential(t *testing.T) {
	for _, name := range []string{"codex", "claudecode"} {
		t.Run(name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			dataDir := filepath.Join(root, "data")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			var conn Connector
			switch name {
			case "codex":
				before := CodexConfigPathOverride
				CodexConfigPathOverride = filepath.Join(root, "codex", "config.toml")
				t.Cleanup(func() { CodexConfigPathOverride = before })
				conn = NewCodexConnector()
			case "claudecode":
				before := ClaudeCodeSettingsPathOverride
				ClaudeCodeSettingsPathOverride = filepath.Join(root, "claude", "settings.json")
				t.Cleanup(func() { ClaudeCodeSettingsPathOverride = before })
				conn = NewClaudeCodeConnector()
			}
			optsFor := func(token string) SetupOpts {
				return SetupOpts{
					DataDir:            dataDir,
					APIAddr:            "127.0.0.1:18970",
					ProxyAddr:          "127.0.0.1:4000",
					APIToken:           token,
					HookAPIToken:       token,
					HookAPITokenScoped: true,
					HookFailMode:       "closed",
					WorkspaceDir:       filepath.Join(root, "workspace"),
				}
			}
			first, err := EnsureHookAPIToken(dataDir, name)
			if err != nil {
				t.Fatal(err)
			}
			stale := optsFor(first)
			if err := conn.Setup(context.Background(), stale); err != nil {
				t.Fatalf("setup: %v", err)
			}
			if err := conn.Teardown(context.Background(), stale); err != nil {
				t.Fatalf("teardown: %v", err)
			}
			if got, _ := LoadHookAPIToken(dataDir, name); got != "" {
				t.Fatal("teardown of the current registration kept its credential")
			}
			second, err := EnsureHookAPIToken(dataDir, name)
			if err != nil || second == first {
				t.Fatalf("re-issue: %v (reused=%v)", err, second == first)
			}
			current := optsFor(second)
			if err := conn.Setup(context.Background(), current); err != nil {
				t.Fatalf("re-add: %v", err)
			}
			// The late teardown of the first registration.
			if err := conn.Teardown(context.Background(), stale); err != nil {
				t.Fatalf("stale teardown: %v", err)
			}
			if got, err := LoadHookAPIToken(dataDir, name); err != nil || got != second {
				t.Fatalf("stale teardown revoked the newer registration's credential: present=%v err=%v", got == second, err)
			}
			if err := conn.Teardown(context.Background(), current); err != nil {
				t.Fatalf("teardown of the re-added registration: %v", err)
			}
			if got, _ := LoadHookAPIToken(dataDir, name); got != "" {
				t.Fatal("teardown of the re-added registration kept its credential")
			}
		})
	}
}
