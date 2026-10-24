// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestConnectorReconcileEveryReplacesAnEarlierReleasesHermesHook(t *testing.T) {
	// The finding: a stopped 1.0.3 install upgraded with Hermes registered
	// keeps the 1.0.3 hermes-hook.sh, which cannot answer this release's
	// execution probe, and the upgrade exited 0. --every-connector renders
	// the current hook, and the registration reads back.
	home := testenv.PrivateTempDir(t)
	testenv.SetHome(t, home)
	// The per-user hook answers for the data dir under HOME it was rendered for.
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	previousConfig := connector.HermesConfigPathOverride
	connector.HermesConfigPathOverride = filepath.Join(home, ".hermes", "config.yaml")
	previousEvery := connectorReconcileEvery
	t.Cleanup(func() {
		connector.HermesConfigPathOverride = previousConfig
		connectorReconcileEvery = previousEvery
	})
	t.Cleanup(withConnectorState(t, dataDir, ""))
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"hermes": {}}
	connectorReconcileEvery = true

	if _, stderr, err := runReconcileEvery(t); err != nil {
		t.Fatalf("first reconcile: %v\nstderr: %s", err, stderr)
	}
	script := filepath.Join(dataDir, "hooks", "hermes-hook.sh")
	current, err := os.ReadFile(script)
	if err != nil || !strings.Contains(string(current), "--defenseclaw-execution-probe") {
		t.Fatalf("rendered Hermes hook %s: err=%v, has the probe=%v", script, err, strings.Contains(string(current), "--defenseclaw-execution-probe"))
	}
	conn, _ := connector.NewDefaultRegistry().Get("hermes")
	opts := reconcileConnectorOpts(dataDir, "hermes")
	if present, err := connector.OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("rendered Hermes registration present=%v err=%v", present, err)
	}

	// The hook an earlier release left: it runs, but has no probe answer.
	if err := os.WriteFile(script, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if present, _ := connector.OwnedHooksPresent(conn, opts); present {
		t.Fatal("an earlier release's Hermes hook read back as current; the fixture does not stand for the finding")
	}

	stdout, stderr, err := runReconcileEvery(t)
	if err != nil {
		t.Fatalf("reconcile over an earlier release's Hermes hook: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "hermes is on its current hook") {
		t.Fatalf("stdout = %q", stdout)
	}
	if present, err := connector.OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("Hermes registration after reconcile present=%v err=%v", present, err)
	}
}
