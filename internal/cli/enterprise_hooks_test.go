// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestWriteEnterpriseHookGuardianState(t *testing.T) {
	dir := t.TempDir()
	rows := []enterpriseHookReconcileRow{
		{User: "alice", Connector: "codex", OK: true},
		{User: "bob", Connector: "claudecode", OK: false, Error: "hook config file missing"},
	}
	if err := writeEnterpriseHookGuardianState(dir, "/etc/defenseclaw/hook-guardian/targets.yaml", rows, 1); err != nil {
		t.Fatalf("writeEnterpriseHookGuardianState: %v", err)
	}
	path := filepath.Join(dir, hookGuardianStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var state enterpriseHookGuardianState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	if state.OK {
		t.Fatalf("state.OK = %v, want false", state.OK)
	}
	if state.TargetCount != 2 || state.SuccessCount != 1 || state.FailureCount != 1 {
		t.Fatalf("counts = target %d success %d failure %d, want 2/1/1", state.TargetCount, state.SuccessCount, state.FailureCount)
	}
	if len(state.Results) != 2 || state.Results[1].Error == "" {
		t.Fatalf("results = %+v, want persisted rows", state.Results)
	}
}

func TestWriteEnterpriseHookGuardianStateRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, hookGuardianStateFile)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := writeEnterpriseHookGuardianState(dir, "manifest.yaml", nil, 0)
	if err == nil || !strings.Contains(err.Error(), "refusing to write through symlink") {
		t.Fatalf("writeEnterpriseHookGuardianState error = %v, want symlink refusal", err)
	}
}

func TestWriteEnterpriseHookGuardianStatePreservesProtectedTargets(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod state dir: %v", err)
	}
	successRows := []enterpriseHookReconcileRow{{
		User:      "alice",
		UserHome:  "/home/alice",
		Connector: "codex",
		OK:        true,
		Result: &enterprisehooks.InstallResult{
			Connector: "codex",
			UserHome:  "/home/alice",
		},
	}}
	if err := writeEnterpriseHookGuardianState(dir, "manifest.yaml", successRows, 0); err != nil {
		t.Fatalf("write initial state: %v", err)
	}
	if !previousEnterpriseHookSuccess(dir, "alice", "/home/alice", "codex") {
		t.Fatal("previousEnterpriseHookSuccess = false after successful state")
	}

	failureRows := []enterpriseHookReconcileRow{{
		User:      "alice",
		UserHome:  "/home/alice",
		Connector: "codex",
		OK:        false,
		Error:     "temporary tamper failure",
	}}
	if err := writeEnterpriseHookGuardianState(dir, "manifest.yaml", failureRows, 1); err != nil {
		t.Fatalf("write failure state: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, hookGuardianStateFile))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var state enterpriseHookGuardianState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	if len(state.ProtectedTargets) != 1 || state.ProtectedTargets[0].Connector != "codex" {
		t.Fatalf("ProtectedTargets = %+v, want preserved codex target", state.ProtectedTargets)
	}
	if !previousEnterpriseHookSuccess(dir, "alice", "/home/alice", "codex") {
		t.Fatal("previousEnterpriseHookSuccess = false after failed state overwrote results")
	}
}

func TestEnterpriseHookScopedTokenUsesManagedDataDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod managed data dir: %v", err)
	}
	token, err := enterpriseHookScopedToken(dir, "codex")
	if err != nil {
		t.Fatalf("enterpriseHookScopedToken: %v", err)
	}
	if token == "" || token == "gateway-token" {
		t.Fatalf("token = %q, want generated scoped token", token)
	}
	path, err := connector.HookAPITokenFilePath(dir, "codex")
	if err != nil {
		t.Fatalf("HookAPITokenFilePath: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scoped token: %v", err)
	}
	if strings.TrimSpace(string(data)) != token {
		t.Fatalf("token file = %q, want generated token", strings.TrimSpace(string(data)))
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("stat scoped token: %v", err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("scoped token mode = %o, want 600", got)
	}
}

func TestEnterpriseHooksReconcileManagedRejectsUntrustedManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "targets.yaml")
	if err := os.WriteFile(manifest, []byte("version: 1\ntargets: []\n"), 0o666); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.Chmod(manifest, 0o666); err != nil {
		t.Fatalf("chmod manifest: %v", err)
	}

	origCfg := cfg
	origManifest := enterpriseHookManifest
	origJSON := enterpriseHookJSON
	origAPIAddr := enterpriseHookAPIAddr
	origProxyAddr := enterpriseHookProxyAddr
	t.Cleanup(func() {
		cfg = origCfg
		enterpriseHookManifest = origManifest
		enterpriseHookJSON = origJSON
		enterpriseHookAPIAddr = origAPIAddr
		enterpriseHookProxyAddr = origProxyAddr
	})

	cfg = &config.Config{DataDir: dir, DeploymentMode: "managed_enterprise"}
	cfg.Gateway.Token = "tok"
	cfg.Gateway.APIPort = 18970
	cfg.Guardrail.Port = 4000
	enterpriseHookManifest = manifest
	enterpriseHookJSON = false
	enterpriseHookAPIAddr = ""
	enterpriseHookProxyAddr = ""

	cmd := &cobra.Command{}
	err := runEnterpriseHooksReconcile(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "manifest trust check failed") {
		t.Fatalf("runEnterpriseHooksReconcile error = %v, want trust check failure", err)
	}
}
