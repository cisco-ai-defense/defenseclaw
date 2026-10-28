// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A connector the selected policy refresh does not take (Kiro) was only read
// back after a stopped upgrade. Its registration names the data-dir script,
// so the hook an earlier release rendered read back as present and the
// upgrade exited 0 on it. --every-connector renders it as the gateway's start
// does and seals the current bytes.
func TestConnectorReconcileEveryReplacesAnEarlierReleasesKiroHook(t *testing.T) {
	dataDir, _, _ := reconcileEveryFixture(t)
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"kiro": {}}

	if _, stderr, err := runReconcileEvery(t); err != nil {
		t.Fatalf("first reconcile: %v\nstderr: %s", err, stderr)
	}
	conn, _ := connector.NewDefaultRegistry().Get("kiro")
	opts := reconcileConnectorOpts(dataDir, "kiro")
	script := filepath.Join(dataDir, "hooks", "kiro-hook.sh")
	current, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("rendered Kiro hook: %v", err)
	}
	if present, err := connector.OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("rendered Kiro registration present=%v err=%v", present, err)
	}

	// The hook an earlier release left in place of this release's script.
	earlier := []byte("#!/usr/bin/env bash\n# kiro hook of an earlier release\nexit 0\n")
	if err := os.WriteFile(script, earlier, 0o700); err != nil {
		t.Fatal(err)
	}
	if present, _ := connector.OwnedHooksPresent(conn, opts); !present {
		t.Fatal("the earlier release's Kiro hook did not read back as present; the fixture does not stand for the finding")
	}

	stdout, stderr, err := runReconcileEvery(t)
	if err != nil {
		t.Fatalf("reconcile over an earlier release's Kiro hook: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "kiro is on its current hook") {
		t.Fatalf("stdout = %q", stdout)
	}
	after, err := os.ReadFile(script)
	if err != nil || !bytes.Equal(after, current) {
		t.Fatalf("Kiro hook after reconcile is not this release's script (err=%v, earlier bytes kept=%v)", err, bytes.Equal(after, earlier))
	}
	sum := sha256.Sum256(after)
	lock := connector.LoadHookContractLockEntry(dataDir, "kiro")
	if got, want := lock.HookScriptDigests["kiro-hook.sh"], "sha256:"+hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("the lock seals kiro-hook.sh as %q, want the rendered bytes %q", got, want)
	}
}
