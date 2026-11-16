//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/spf13/cobra"
)

// GAP-0013: an unpinned LocalSystem or administrator run of the enterprise
// hooks commands against a standalone install takes the standalone profile
// from the protected config, so the renderer keeps fail-closed delivery and
// its agent-version gates. A Secure Client install never gets the pin.
func TestWindowsEnterpriseHooksPreRunAdoptsTheResolvedStandaloneProfile(t *testing.T) {
	originalRuntimeGOOS := enterpriseHooksRuntimeGOOS
	originalLoader := enterpriseHooksWindowsConfigLoader
	originalCfg := cfg
	t.Cleanup(func() {
		enterpriseHooksRuntimeGOOS = originalRuntimeGOOS
		enterpriseHooksWindowsConfigLoader = originalLoader
		cfg = originalCfg
	})
	enterpriseHooksRuntimeGOOS = func() string { return "windows" }
	for _, tc := range []struct {
		profile string
		want    string
	}{
		{managed.ProfileStandalone, managed.ProfileStandalone},
		{managed.ProfileSecureClient, ""},
		{"", ""}, // the Windows default profile is Secure Client
	} {
		t.Run("profile="+tc.profile, func(t *testing.T) {
			t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
			t.Setenv(managed.EnterpriseProfileEnv, "")
			enterpriseHooksWindowsConfigLoader = func() (*config.Config, error) {
				loaded := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: t.TempDir()}
				loaded.Enterprise.Profile = tc.profile
				return loaded, nil
			}
			if err := enterpriseHooksNativePersistentPreRun(&cobra.Command{}, nil); err != nil {
				t.Fatalf("pre-run: %v", err)
			}
			if got := os.Getenv(managed.EnterpriseProfileEnv); got != tc.want {
				t.Fatalf("%s = %q after loading a %q config, want %q", managed.EnterpriseProfileEnv, got, tc.profile, tc.want)
			}
		})
	}
}
