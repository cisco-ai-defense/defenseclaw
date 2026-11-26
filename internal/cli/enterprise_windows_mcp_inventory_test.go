// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
)

func TestEnterpriseWindowsMCPInventoryPublicationProfiles(t *testing.T) {
	for _, test := range []struct {
		name, mode, profile string
		discovery, publish  bool
	}{
		{"secure-client-on", "managed_enterprise", managed.ProfileSecureClient, true, true},
		{"secure-client-off", "managed_enterprise", managed.ProfileSecureClient, false, false},
		{"standalone-on", "managed_enterprise", managed.ProfileStandalone, true, true},
		{"standalone-off", "managed_enterprise", managed.ProfileStandalone, false, true},
		{"opensource", "opensource", "", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			previousOwner := enterpriseHookAuthorizationOwnershipSetter
			enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
			t.Cleanup(func() { enterpriseHookAuthorizationOwnershipSetter = previousOwner })
			previous := enterpriseWindowsMCPSpoolWriter
			t.Cleanup(func() { enterpriseWindowsMCPSpoolWriter = previous })
			writes := 0
			enterpriseWindowsMCPSpoolWriter = func(dir, connector string, _ enterprisehooks.Manifest, _ func(string) error, _ func(string, ...any)) error {
				writes++
				if dir == "" || !filepath.IsAbs(dir) || !mcpasuser.PublishedConnector(connector) {
					t.Fatalf("invalid spool target %q/%q", dir, connector)
				}
				return nil
			}
			cfg := &config.Config{DataDir: t.TempDir(), DeploymentMode: test.mode}
			cfg.Enterprise.Profile = test.profile
			cfg.AIDiscovery.Enabled = test.discovery
			if err := publishEnterpriseWindowsMCPServers(cfg, enterprisehooks.Manifest{}, io.Discard); err != nil {
				t.Fatal(err)
			}
			want := 0
			if test.publish {
				want = len(mcpasuser.PublishedConnectors())
			}
			if writes != want {
				t.Fatalf("spool writes=%d, want %d", writes, want)
			}
		})
	}
}

func TestSecureClientWindowsEnumerateReportsMCPPublicationFailure(t *testing.T) {
	previousConfig, previousEnumerator := enterpriseWindowsEnumerateConfigLoader, enterpriseWindowsEnumerateProfileEnumerator
	previousWriter, previousSpool := enterpriseWindowsEnumerateManifestWriter, enterpriseWindowsMCPSpoolWriter
	previousOwner := enterpriseHookAuthorizationOwnershipSetter
	t.Cleanup(func() {
		enterpriseWindowsEnumerateConfigLoader, enterpriseWindowsEnumerateProfileEnumerator = previousConfig, previousEnumerator
		enterpriseWindowsEnumerateManifestWriter, enterpriseWindowsMCPSpoolWriter = previousWriter, previousSpool
		enterpriseHookAuthorizationOwnershipSetter = previousOwner
	})
	cfg := &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	cfg.AIDiscovery.Enabled = true
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return cfg, nil }
	enterpriseWindowsEnumerateProfileEnumerator = func(context.Context, *config.Config, enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		return enterprisehooks.Manifest{Version: 1}, nil
	}
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return false, nil }
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseWindowsMCPSpoolWriter = func(_, _ string, _ enterprisehooks.Manifest, _ func(string) error, _ func(string, ...any)) error {
		return errors.New("publication denied")
	}
	err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), io.Discard, filepath.Join(t.TempDir(), "targets.yaml"))
	var incomplete *mcpasuser.RefreshIncomplete
	if !errors.As(err, &incomplete) || len(incomplete.Connectors) != len(mcpasuser.PublishedConnectors()) {
		t.Fatalf("cycle swallowed publication failures: %v", err)
	}
	for _, connector := range mcpasuser.PublishedConnectors() {
		dir := enterprisehooks.MCPSpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir), connector.Connector)
		if err := enterprisehooks.ReadMCPInventoryPublication(dir, nil); err == nil {
			t.Fatalf("%s receipt remained ready", connector.Connector)
		}
	}
}
