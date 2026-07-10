// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
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

func newPrivateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod private dir: %v", err)
	}
	return dir
}
