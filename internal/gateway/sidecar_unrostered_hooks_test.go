// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// An install that later guards only OpenClaw kept the DefenseClaw Kiro hook
// file a rollback had rewritten: Kiro was in no active roster and no lock,
// so no boot tore it down, and every Kiro call failed closed for want of the
// token the earlier teardown had revoked (rel-1-0-10:GAP-0275). A boot
// removes the DefenseClaw hooks of a connector this install once set up (its
// hook script is in the hooks folder) that it no longer guards, and leaves a
// guarded, a rostered and a never set up connector alone.
func TestBootRemovesHooksOfAConnectorTheInstallNoLongerGuards(t *testing.T) {
	home := t.TempDir()
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	hooksFile := filepath.Join(home, ".kiro", "hooks", "defenseclaw.json")
	entry := func(command string) string {
		return `{"version":"v1","hooks":[{"name":"defenseclaw-pre-tool","trigger":"PreToolUse","matcher":".*",` +
			`"action":{"type":"command","command":"` + command + `"},"timeout":30,"enabled":true}]}` + "\n"
	}
	stale := entry(filepath.Join(dataDir, "hooks", "kiro-hook.sh") + " --hook-surface v3")
	foreign := entry("/other/defenseclaw-home/hooks/kiro-hook.sh --hook-surface v3")
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{DataDir: dataDir}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = "openclaw"
	s := &Sidecar{cfg: cfg}
	registry := connector.NewDefaultRegistry()
	kiroHasHooks := func() bool {
		data, err := os.ReadFile(hooksFile)
		return err == nil && strings.Contains(string(data), "defenseclaw-")
	}

	// Never set up by this install (no kiro-hook.sh): left alone.
	write(hooksFile, stale)
	s.reclaimUnguardedConnectorHooks(context.Background(), registry)
	if !kiroHasHooks() {
		t.Fatal("hooks of a connector this install never set up were removed")
	}

	// Set up once, now unguarded and in no roster or lock, but the hooks name
	// another DefenseClaw data directory: left alone.
	script := filepath.Join(dataDir, "hooks", "kiro-hook.sh")
	write(script, "#!/bin/sh\nexit 0\n")
	write(hooksFile, foreign)
	s.reclaimUnguardedConnectorHooks(context.Background(), registry)
	if !kiroHasHooks() {
		t.Fatal("the hooks of another DefenseClaw data directory were removed")
	}

	// This install's own hooks: removed with the hook script, and the next boot
	// finds nothing to do.
	write(hooksFile, stale)
	for boot := 1; boot <= 2; boot++ {
		s.reclaimUnguardedConnectorHooks(context.Background(), registry)
		if kiroHasHooks() {
			t.Fatalf("boot %d: the unguarded Kiro hooks are still there", boot)
		}
	}
	if _, err := os.Lstat(script); !os.IsNotExist(err) {
		t.Fatalf("the hook script of the unguarded connector is still there: %v", err)
	}
	write(script, "#!/bin/sh\nexit 0\n")

	// Guarded, or still in the active roster (the set-difference teardown
	// owns that one): left alone.
	for _, guarded := range []func(){
		func() { cfg.Guardrail.Connector = "kiro" },
		func() {
			cfg.Guardrail.Connector = "openclaw"
			if err := connector.SaveActiveConnectors(dataDir, []string{"kiro"}); err != nil {
				t.Fatal(err)
			}
		},
	} {
		guarded()
		write(hooksFile, stale)
		s.reclaimUnguardedConnectorHooks(context.Background(), registry)
		if !kiroHasHooks() {
			t.Fatal("hooks of a guarded or rostered connector were removed")
		}
	}
}
