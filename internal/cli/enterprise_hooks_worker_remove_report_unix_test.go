//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestEnterpriseHookWorkerRemoveReportsPathsAndRemainingEntries(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the per-user remover requires a non-root test account")
	}
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	previousPath := connector.OpenCodePluginPathOverride
	connector.OpenCodePluginPathOverride = ""
	t.Cleanup(func() { connector.OpenCodePluginPathOverride = previousPath })
	home := t.TempDir()
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "opencode", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
		GuardrailMode: "action", HookFailMode: "closed", AgentVersion: "2.1.4",
		Registry: connector.NewDefaultRegistry(),
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js")
	receipt := filepath.Join(home, ".defenseclaw", "connector_backups", "opencode", "config.json")
	if _, err := os.Stat(receipt); err != nil {
		t.Fatal(err)
	}
	request := enterpriseHookWorkerRequest{Home: home, UID: os.Getuid(), GID: os.Getgid(),
		Targets: []enterpriseHookWorkerTarget{{Index: 0, Mode: enterpriseHookWorkerModeRemove,
			Options: enterpriseHookWorkerOptionsFrom(opts)}},
	}
	previousRemover, previousVerifier := enterpriseHookWorkerRemover, enterpriseHookWorkerVerifier
	t.Cleanup(func() { enterpriseHookWorkerRemover, enterpriseHookWorkerVerifier = previousRemover, previousVerifier })
	enterpriseHookWorkerRemover = func(context.Context, enterprisehooks.InstallOptions) error { return nil }
	first := runEnterpriseHookWorkerApply(context.Background(), request).Targets[0]
	if !first.OK || !first.PathsReported || !strings.Contains(first.Remaining, plugin) ||
		len(first.CleanedPaths) == 0 {
		t.Fatalf("remove without teardown lost paths or residual: %+v", first)
	}
	foundPlugin := false
	for _, path := range first.CleanedPaths {
		foundPlugin = foundPlugin || path == plugin
	}
	if !foundPlugin {
		t.Fatalf("remove report omitted plugin path: %+v", first)
	}
	enterpriseHookWorkerRemover = previousRemover
	second := runEnterpriseHookWorkerApply(context.Background(), request).Targets[0]
	if !second.OK || !second.PathsReported || second.Remaining != "" {
		t.Fatalf("successful removal was not reported clean: %+v", second)
	}
	if _, err := os.Lstat(plugin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plugin remains: %v", err)
	}

	// Install/verify replies still omit the new Remove-only JSON fields.
	result := enterprisehooks.InstallResult{Connector: "opencode", UserHome: home}
	enterpriseHookWorkerVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return result, nil
	}
	request.Targets[0].Mode = enterpriseHookWorkerModeVerify
	verify := runEnterpriseHookWorkerApply(context.Background(), request).Targets[0]
	encoded, err := json.Marshal(verify)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(enterpriseHookWorkerTargetResult{Index: 0, OK: true, Result: &result})
	if err != nil || string(encoded) != string(want) || strings.Contains(string(encoded), "paths_reported") ||
		strings.Contains(string(encoded), "cleaned_paths") || strings.Contains(string(encoded), "remaining") {
		t.Fatalf("verify JSON changed: %s, want %s, err %v", encoded, want, err)
	}
}
