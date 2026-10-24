// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// A published predecessor may record either outage mode. Upgrade publishes
// the current tier's mode, rejects a different runtime record, and restores
// the predecessor lock if publication must roll back.
func TestCodexUpgradePreservesTierAndRestoresPredecessorLock(t *testing.T) {
	for _, predecessor := range []string{"1.0.0", "1.0.1", "1.0.2", "1.0.3"} {
		for _, priorMode := range []string{"open", "closed"} {
			for _, tier := range []string{"default", "strict"} {
				t.Run(predecessor+"/"+priorMode+"/"+tier, func(t *testing.T) {
					testCodexUpgradePredecessorLock(t, predecessor, priorMode, tier)
				})
			}
		}
	}
}

func testCodexUpgradePredecessorLock(t *testing.T, predecessor, priorMode, tier string) {
	t.Helper()
	dataDir := testenv.PrivateTempDir(t)
	codexHome := testenv.PrivateTempDir(t)
	runtimeHome := testenv.PrivateTempDir(t)
	testenv.SetHome(t, runtimeHome)
	trustConfig, err := json.Marshal(map[string]interface{}{
		"ai_discovery": map[string]interface{}{
			"require_trusted_binary_paths": true,
			"trusted_binary_prefixes":      []string{dataDir},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), trustConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	previousConfigPath := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = filepath.Join(codexHome, "config.toml")
	t.Cleanup(func() { connector.CodexConfigPathOverride = previousConfigPath })
	t.Setenv("CODEX_HOME", codexHome)
	launcherDir := filepath.Join(runtimeHome, ".local", "bin")
	if err := os.MkdirAll(launcherDir, 0o700); err != nil {
		t.Fatal(err)
	}
	token, err := connector.EnsureHookAPIToken(dataDir, "codex")
	if err != nil {
		t.Fatal(err)
	}
	conn := connector.NewCodexConnector()
	wantMode := "open"
	if tier == "strict" {
		wantMode = "closed"
	}
	opts := connector.SetupOpts{
		DataDir: dataDir, APIAddr: "127.0.0.1:18970",
		APIToken: token, HookAPIToken: token, HookAPITokenScoped: true,
		HookFailMode: wantMode,
	}
	prepareCodexSetupPolicyFixture(t, dataDir, &opts)
	if err := os.Link(opts.AgentExecutable, filepath.Join(launcherDir, "defenseclaw-hook.exe")); err != nil {
		t.Fatal(err)
	}
	priorOpts := opts
	priorOpts.HookFailMode = priorMode
	prior := connector.NewHookContractLockEntry(priorOpts, conn, predecessor)
	prior.HookFailMode = priorMode
	if err := connector.SaveHookContractLockEntry(dataDir, prior); err != nil {
		t.Fatal(err)
	}
	priorSnapshot, err := connector.CaptureHookContractLockSnapshot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.DataDir = dataDir
	cfg.Gateway.Token = "test-gateway-token"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Mode = "observe"
	s := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	if err := s.setupOneConnector(context.Background(), conn, opts, cfg.Gateway.Token, guardrail.NewRulePackCache()); err != nil {
		t.Fatalf("upgrade from %s: %v", predecessor, err)
	}
	got := connector.LoadHookContractLockEntry(dataDir, "codex")
	if got.HookFailMode != wantMode || got.DefenseClawVersion != version.Current().BinaryVersion {
		t.Fatalf("upgraded lock = mode %q release %q, want %s current release", got.HookFailMode, got.DefenseClawVersion, wantMode)
	}
	if current, err := connector.HookRuntimeRegistrationCurrent(opts, conn, version.Current().BinaryVersion); err != nil || !current {
		t.Fatalf("upgraded registration current=%v err=%v", current, err)
	}
	flatPath := filepath.Join(dataDir, "hooks", ".hookcfg.codex")
	flat, err := os.ReadFile(flatPath)
	if err != nil {
		t.Fatal(err)
	}
	otherMode := "closed"
	if wantMode == "closed" {
		otherMode = "open"
	}
	tampered := bytes.Replace(flat, []byte("DEFENSECLAW_FAIL_MODE="+wantMode), []byte("DEFENSECLAW_FAIL_MODE="+otherMode), 1)
	if bytes.Equal(tampered, flat) {
		t.Fatalf("fresh Codex runtime record did not contain %s: %q", wantMode, flat)
	}
	if err := os.WriteFile(flatPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if current, err := connector.HookRuntimeRegistrationCurrent(opts, conn, version.Current().BinaryVersion); err != nil || current {
		t.Fatalf("tampered runtime record current=%v err=%v, want refusal", current, err)
	}

	// A later publication error reapplies the prior registration and
	// restores its old lock after checking the restored registration.
	if err := conn.Setup(context.Background(), priorOpts); err != nil {
		t.Fatal(err)
	}
	if err := priorSnapshot.Restore(); err != nil {
		t.Fatal(err)
	}
	point := multiConnectorSetupRollbackPoint{
		conn: conn, opts: opts, previouslyActive: true, previousLock: prior,
	}
	if err := verifyPreviouslyActiveConnectorRollback(point); err != nil {
		t.Fatalf("rollback to %s posture: %v", predecessor, err)
	}
	if restored := connector.LoadHookContractLockEntry(dataDir, "codex"); restored.HookFailMode != priorMode || restored.DefenseClawVersion != predecessor {
		t.Fatalf("rollback lock = mode %q release %q, want predecessor %s lock", restored.HookFailMode, restored.DefenseClawVersion, priorMode)
	}
	flat, err = os.ReadFile(flatPath)
	if err != nil {
		t.Fatal(err)
	}
	otherMode = "closed"
	if priorMode == "closed" {
		otherMode = "open"
	}
	tampered = bytes.Replace(flat, []byte("DEFENSECLAW_FAIL_MODE="+priorMode), []byte("DEFENSECLAW_FAIL_MODE="+otherMode), 1)
	if bytes.Equal(tampered, flat) {
		t.Fatalf("restored Codex runtime record did not contain %s: %q", priorMode, flat)
	}
	if err := os.WriteFile(flatPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPreviouslyActiveConnectorRollback(point); err == nil {
		t.Fatal("rollback accepted a runtime record outside the predecessor contract")
	}
	if restored := connector.LoadHookContractLockEntry(dataDir, "codex"); restored.HookFailMode != priorMode || restored.DefenseClawVersion != predecessor {
		t.Fatalf("failed rollback check lost predecessor lock: mode %q release %q", restored.HookFailMode, restored.DefenseClawVersion)
	}
}
