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

// Kiro was only read back after a stopped upgrade, when the selected policy
// refresh did not take it. Its registration names the data-dir script,
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

// A selected refresh of Kiro (what `guardrail fail-mode --connector kiro`
// runs) was refused with "selected refresh is supported only for ...", and
// the fail-mode change was rolled back on every install (rel-1-0-6
// GAP-0576). It renders Kiro's hook as the gateway's start does and seals
// the saved per-connector outage mode, closed and then open, in the lock the
// fail-mode check reads back.
func TestConnectorReconcileSelectedKiroAppliesEachFailMode(t *testing.T) {
	dataDir, _, _ := reconcileEveryFixture(t)
	connectorReconcileEvery = false
	previousName, previousJSON := connectorFlagName, connectorFlagJSON
	t.Cleanup(func() { connectorFlagName, connectorFlagJSON = previousName, previousJSON })
	connectorFlagName, connectorFlagJSON = "kiro", true
	conn, _ := connector.NewDefaultRegistry().Get("kiro")

	for _, mode := range []string{"closed", "open"} {
		cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"kiro": {HookFailMode: mode}}
		stdout, stderr, err := runReconcileEvery(t)
		if err != nil {
			t.Fatalf("reconcile --connector kiro (%s): %v\nstderr: %s", mode, err, stderr)
		}
		if !strings.Contains(stdout, `"connector":"kiro"`) || !strings.Contains(stdout, `"fail_mode":"`+mode+`"`) {
			t.Fatalf("reconcile --connector kiro (%s) stdout = %q", mode, stdout)
		}
		opts := reconcileConnectorOpts(dataDir, "kiro")
		if present, err := connector.OwnedHooksPresent(conn, opts); err != nil || !present {
			t.Fatalf("Kiro registration after reconcile (%s): present=%v err=%v", mode, present, err)
		}
		script, err := os.ReadFile(filepath.Join(dataDir, "hooks", "kiro-hook.sh"))
		if err != nil {
			t.Fatalf("rendered Kiro hook (%s): %v", mode, err)
		}
		sum := sha256.Sum256(script)
		lock := connector.LoadHookContractLockEntry(dataDir, "kiro")
		if lock.Connector != "kiro" || lock.HookFailMode != mode {
			t.Fatalf("Kiro lock after reconcile (%s) = %+v, want the saved outage mode", mode, lock)
		}
		if got, want := lock.HookScriptDigests["kiro-hook.sh"], "sha256:"+hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("the lock seals kiro-hook.sh as %q, want the rendered bytes %q (%s)", got, want, mode)
		}
	}
}
