// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestEnterpriseHookScopedTokenRefusesSymlinkDataDir(t *testing.T) {
	target := t.TempDir()
	dataDir := filepath.Join(t.TempDir(), "defenseclaw")
	if err := os.Symlink(target, dataDir); err != nil {
		t.Fatalf("symlink data dir: %v", err)
	}

	_, err := enterpriseHookScopedToken(dataDir, "codex")
	if err == nil || !strings.Contains(err.Error(), "refusing symlink managed data_dir") {
		t.Fatalf("enterpriseHookScopedToken error = %v, want symlink data_dir refusal", err)
	}
	if entries, readErr := os.ReadDir(target); readErr != nil || len(entries) != 0 {
		t.Fatalf("symlink target changed: entries=%v err=%v", entries, readErr)
	}
}

func TestEnterpriseHookScopedTokenRefusesSymlinkTokenDir(t *testing.T) {
	dataDir := newPrivateDir(t)
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dataDir, "hooks")); err != nil {
		t.Fatalf("symlink hooks dir: %v", err)
	}

	_, err := enterpriseHookScopedToken(dataDir, "codex")
	if err == nil || !strings.Contains(err.Error(), "refusing symlink hook token dir") {
		t.Fatalf("enterpriseHookScopedToken error = %v, want symlink token dir refusal", err)
	}
	if entries, readErr := os.ReadDir(target); readErr != nil || len(entries) != 0 {
		t.Fatalf("symlink target changed: entries=%v err=%v", entries, readErr)
	}
}

func TestEnterpriseHookScopedTokenRefusesSymlinkTokenFile(t *testing.T) {
	dataDir := newPrivateDir(t)
	tokenPath, err := connector.HookAPITokenFilePath(dataDir, "codex")
	if err != nil {
		t.Fatalf("HookAPITokenFilePath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatalf("mkdir hooks dir: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside.token")
	if err := os.WriteFile(outside, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatalf("write outside token: %v", err)
	}
	if err := os.Symlink(outside, tokenPath); err != nil {
		t.Fatalf("symlink token: %v", err)
	}

	_, err = enterpriseHookScopedToken(dataDir, "codex")
	if err == nil || !strings.Contains(err.Error(), "refusing symlink hook token") {
		t.Fatalf("enterpriseHookScopedToken error = %v, want symlink token refusal", err)
	}
	if got, readErr := os.ReadFile(outside); readErr != nil || string(got) != strings.Repeat("a", 64)+"\n" {
		t.Fatalf("outside token changed: data=%q err=%v", string(got), readErr)
	}
}

func TestEnterpriseHooksInstallJSONCoversTokenPreflightFailure(t *testing.T) {
	target := t.TempDir()
	dataDir := filepath.Join(t.TempDir(), "defenseclaw")
	if err := os.Symlink(target, dataDir); err != nil {
		t.Fatalf("symlink data dir: %v", err)
	}
	home := newPrivateDir(t)

	origCfg := cfg
	origConnector := enterpriseHookConnector
	origUser := enterpriseHookUser
	origUserHome := enterpriseHookUserHome
	origUID := enterpriseHookUID
	origGID := enterpriseHookGID
	origDataDir := enterpriseHookDataDir
	origAPIAddr := enterpriseHookAPIAddr
	origProxyAddr := enterpriseHookProxyAddr
	origAgentVersion := enterpriseHookAgentVersion
	origJSON := enterpriseHookJSON
	t.Cleanup(func() {
		cfg = origCfg
		enterpriseHookConnector = origConnector
		enterpriseHookUser = origUser
		enterpriseHookUserHome = origUserHome
		enterpriseHookUID = origUID
		enterpriseHookGID = origGID
		enterpriseHookDataDir = origDataDir
		enterpriseHookAPIAddr = origAPIAddr
		enterpriseHookProxyAddr = origProxyAddr
		enterpriseHookAgentVersion = origAgentVersion
		enterpriseHookJSON = origJSON
	})

	cfg = &config.Config{DataDir: dataDir}
	cfg.Gateway.APIPort = 18970
	cfg.Guardrail.Port = 4000
	enterpriseHookConnector = "codex"
	enterpriseHookUser = ""
	enterpriseHookUserHome = home
	enterpriseHookUID = os.Getuid()
	enterpriseHookGID = os.Getgid()
	enterpriseHookDataDir = ""
	enterpriseHookAPIAddr = ""
	enterpriseHookProxyAddr = ""
	enterpriseHookAgentVersion = "codex-cli 0.142.0"
	enterpriseHookJSON = true

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runEnterpriseHooksInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "enterprise hooks install failed") {
		t.Fatalf("runEnterpriseHooksInstall error = %v, want generic JSON install failure", err)
	}
	var payload map[string]any
	if decodeErr := json.Unmarshal(out.Bytes(), &payload); decodeErr != nil {
		t.Fatalf("decode JSON output %q: %v", out.String(), decodeErr)
	}
	if payload["ok"] != false || !strings.Contains(payload["error"].(string), "refusing symlink managed data_dir") {
		t.Fatalf("payload = %#v, want JSON token preflight failure", payload)
	}
}

func TestEnterpriseHooksInstallPassesExplicitAgentExecutable(t *testing.T) {
	serviceData := newPrivateDir(t)
	home := newPrivateDir(t)
	executable := filepath.Join(home, "clients", "codex")

	origCfg := cfg
	origConnector := enterpriseHookConnector
	origUser := enterpriseHookUser
	origUserHome := enterpriseHookUserHome
	origUID := enterpriseHookUID
	origGID := enterpriseHookGID
	origSID := enterpriseHookSID
	origDataDir := enterpriseHookDataDir
	origAgentVersion := enterpriseHookAgentVersion
	origAgentExecutable := enterpriseHookAgentExecutable
	origJSON := enterpriseHookJSON
	origInstall := enterpriseHooksInstallTarget
	t.Cleanup(func() {
		cfg = origCfg
		enterpriseHookConnector = origConnector
		enterpriseHookUser = origUser
		enterpriseHookUserHome = origUserHome
		enterpriseHookUID = origUID
		enterpriseHookGID = origGID
		enterpriseHookSID = origSID
		enterpriseHookDataDir = origDataDir
		enterpriseHookAgentVersion = origAgentVersion
		enterpriseHookAgentExecutable = origAgentExecutable
		enterpriseHookJSON = origJSON
		enterpriseHooksInstallTarget = origInstall
	})

	cfg = &config.Config{DataDir: serviceData}
	cfg.Gateway.APIPort = 18970
	cfg.Guardrail.Port = 4000
	enterpriseHookConnector = "codex"
	enterpriseHookUser = ""
	enterpriseHookUserHome = home
	enterpriseHookUID = os.Getuid()
	enterpriseHookGID = os.Getgid()
	enterpriseHookSID = ""
	enterpriseHookDataDir = ""
	enterpriseHookAgentVersion = "codex-cli 0.146.0"
	enterpriseHookAgentExecutable = executable
	enterpriseHookJSON = false

	var captured enterprisehooks.InstallOptions
	enterpriseHooksInstallTarget = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		captured = opts
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&bytes.Buffer{})
	if err := runEnterpriseHooksInstall(cmd, nil); err != nil {
		t.Fatalf("runEnterpriseHooksInstall: %v", err)
	}
	if captured.AgentExecutable != executable || captured.AgentVersion != "codex-cli 0.146.0" {
		t.Fatalf("InstallOptions selection = version %q executable %q", captured.AgentVersion, captured.AgentExecutable)
	}
}

func TestEnterpriseHooksReconcilePassesManifestAgentExecutable(t *testing.T) {
	serviceData := newPrivateDir(t)
	authorizationDir := newPrivateDir(t)
	t.Setenv(hookGuardianAuthorizationDirEnv, authorizationDir)
	home := newPrivateDir(t)
	executable := filepath.Join(home, "clients", "claude")
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	body := fmt.Sprintf(
		"version: 1\ntargets:\n  - user_home: %q\n    uid: %d\n    gid: %d\n    connector: claudecode\n    agent_version: %q\n    agent_executable: %q\n",
		home,
		os.Getuid(),
		os.Getgid(),
		"2.1.219 (Claude Code)",
		executable,
	)
	if err := os.WriteFile(manifest, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	origCfg := cfg
	origManifest := enterpriseHookManifest
	origAPIAddr := enterpriseHookAPIAddr
	origProxyAddr := enterpriseHookProxyAddr
	origInstall := enterpriseHooksInstallTarget
	origOwnership := enterpriseHookAuthorizationOwnershipSetter
	t.Cleanup(func() {
		cfg = origCfg
		enterpriseHookManifest = origManifest
		enterpriseHookAPIAddr = origAPIAddr
		enterpriseHookProxyAddr = origProxyAddr
		enterpriseHooksInstallTarget = origInstall
		enterpriseHookAuthorizationOwnershipSetter = origOwnership
	})
	cfg = &config.Config{DataDir: serviceData}
	cfg.Gateway.APIPort = 18970
	cfg.Guardrail.Port = 4000
	enterpriseHookManifest = manifest
	enterpriseHookAPIAddr = ""
	enterpriseHookProxyAddr = ""
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }

	var captured enterprisehooks.InstallOptions
	enterpriseHooksInstallTarget = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		captured = opts
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatalf("runEnterpriseHookReconcileOnce: %v", err)
	}
	if run.Failures != 0 || run.StateErr != nil {
		t.Fatalf("reconcile result = failures %d stateErr %v rows %+v", run.Failures, run.StateErr, run.Rows)
	}
	if captured.AgentExecutable != executable || captured.AgentVersion != "2.1.219 (Claude Code)" {
		t.Fatalf("reconcile InstallOptions selection = version %q executable %q", captured.AgentVersion, captured.AgentExecutable)
	}
}

func newPrivateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod private dir: %v", err)
	}
	return dir
}
