//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterprise acp enroll, verify and revoke --user resolve an Entra ID account
// through the LSA and ProfileList when os/user cannot (GAP-0479).
func TestEnterpriseHookTargetResolvesAnEntraIDAccount(t *testing.T) {
	const sid = "S-1-12-1-1111111111-2222222222-3333333333-4444444444"
	previousAccount, previousHome, previousCfg := enterprisePolicyAccount, enterprisePolicyProfileHome, cfg
	t.Cleanup(func() {
		enterprisePolicyAccount, enterprisePolicyProfileHome, cfg = previousAccount, previousHome, previousCfg
	})
	cfg = nil
	enterprisePolicyAccount = func(name string) (string, string, error) {
		if name != `AzureAD\EntraAlice` {
			return "", "", errors.New("No mapping between account names and security IDs was done")
		}
		return sid, "EntraAlice", nil
	}
	enterprisePolicyProfileHome = func(id string) string {
		if id == sid {
			return `C:\Users\EntraAlice`
		}
		return ""
	}
	target, err := resolveEnterpriseHookTargetValues(`AzureAD\EntraAlice`, "", -1, -1, "", "")
	if err != nil || target.sid != sid || target.home != `C:\Users\EntraAlice` {
		t.Fatalf("target = %+v, %v; want the Entra account's SID and profile", target, err)
	}
}

// GAP-0716: the guardian takes a changed managed config before it
// reconciles, without a restart; a config that does not load is ignored.
func TestEnterpriseHookStandaloneConfigRefreshTakesAChangedConfig(t *testing.T) {
	previousCfg, previousLoader, previousLoaded := cfg, enterpriseHookWindowsConfigLoader, enterpriseHookWindowsLoadedConfig
	t.Cleanup(func() {
		cfg, enterpriseHookWindowsConfigLoader, enterpriseHookWindowsLoadedConfig = previousCfg, previousLoader, previousLoaded
	})
	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	standalone := func(exclude ...string) *config.Config {
		c := config.DefaultConfig()
		c.DeploymentMode = managed.DeploymentModeManagedEnterprise
		c.Enterprise.Profile = managed.ProfileStandalone
		c.Enterprise.Enrollment.ExcludeUsers = exclude
		c.ConfigFilePath = path
		return c
	}
	write("exclude_users: [a]\n")
	cfg = standalone("a")
	var loadErr error
	enterpriseHookWindowsConfigLoader = func(string) (*config.Config, error) { return standalone("a", "b"), loadErr }
	enterpriseHookStandaloneConfigFingerprint()

	enterpriseHookStandaloneConfigRefresh(io.Discard)
	if len(cfg.Enterprise.Enrollment.ExcludeUsers) != 1 {
		t.Fatalf("an unchanged config was reloaded: %v", cfg.Enterprise.Enrollment.ExcludeUsers)
	}
	write("exclude_users: [a, b]\n")
	enterpriseHookStandaloneConfigRefresh(io.Discard)
	if len(cfg.Enterprise.Enrollment.ExcludeUsers) != 2 {
		t.Fatalf("exclude_users = %v after the change, want [a b]", cfg.Enterprise.Enrollment.ExcludeUsers)
	}
	loadErr = errors.New("does not validate")
	write("exclude_users: [a, b, c]\n")
	enterpriseHookStandaloneConfigRefresh(io.Discard)
	if len(cfg.Enterprise.Enrollment.ExcludeUsers) != 2 {
		t.Fatalf("a config that does not load replaced the running one: %v", cfg.Enterprise.Enrollment.ExcludeUsers)
	}
}
