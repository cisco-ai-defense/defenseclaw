//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An upgrade: a standalone Hermes hook installed before it ran the
// foreign-hook guard fails Verify once the guard is configured, so the
// guardian's verify-or-repair pass re-renders hermes-hook.sh with it, and
// passes again after that Install. The registered Hermes command (the
// per-user hermes-hook.sh) does not change.
func TestVerifyFailsWhenTheHermesHookPredatesTheForeignHookGuard(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	before := hermesStandaloneOptions(t, home)
	before.ManagedHookSocket = "/var/run/defenseclaw/hook.sock"
	before.ManagedServiceUID = 461
	guarded := before
	guarded.ForeignHookGuardBinary = "/opt/cisco/defenseclaw/bin/defenseclaw-hook"
	script := filepath.Join(home, ".defenseclaw", "hooks", "hermes-hook.sh")
	configPath := filepath.Join(home, ".hermes", "config.yaml")
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	const drift = "different foreign-hook guard"

	if _, err := Install(context.Background(), before); err != nil {
		t.Fatalf("Install (no guard): %v", err)
	}
	if strings.Contains(read(script), "foreign-hook-check") {
		t.Fatal("an install without the guard rendered it")
	}
	registered := read(configPath)
	if _, err := Verify(context.Background(), before); err != nil {
		t.Fatalf("Verify (no guard configured): %v", err)
	}
	if _, err := Verify(context.Background(), guarded); err == nil || !strings.Contains(err.Error(), drift) {
		t.Fatalf("Verify (guard configured) = %v, want the guard drift", err)
	}

	if _, err := Install(context.Background(), guarded); err != nil {
		t.Fatalf("Install (guard): %v", err)
	}
	if hook := read(script); !strings.Contains(hook, "DEFENSECLAW_FOREIGN_GUARD='/opt/cisco/defenseclaw/bin/defenseclaw-hook'") {
		t.Fatal("the guarded install did not render the guard")
	}
	if read(configPath) != registered {
		t.Fatal("rendering the guard must not change the Hermes registration")
	}
	if _, err := Verify(context.Background(), guarded); err != nil {
		t.Fatalf("Verify (guarded install): %v", err)
	}
	if _, err := Verify(context.Background(), before); err == nil || !strings.Contains(err.Error(), drift) {
		t.Fatalf("Verify (guard removed from the configuration) = %v, want the guard drift", err)
	}
}
