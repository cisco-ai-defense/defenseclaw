// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
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
