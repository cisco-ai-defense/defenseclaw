// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0002: a managed Config the loader never resolved reports Secure Client
// from EnterpriseProfile, and #1163 made Secure Client hooks fail open when
// the fail mode is unset. On Linux, where Secure Client does not exist, such
// a config must keep the fail-closed rules; an explicit Secure Client profile
// keeps #1163 on every OS.
func TestUnresolvedManagedProfileNeverOpensHooksOnLinux(t *testing.T) {
	for _, tc := range []struct {
		profile string
		want    string
	}{
		{"", map[bool]string{true: "closed", false: "open"}[runtime.GOOS == "linux"]},
		{managed.ProfileStandalone, "closed"},
		{managed.ProfileSecureClient, "open"},
	} {
		cfg := &Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
		cfg.Enterprise.Profile = tc.profile
		cfg.Guardrail.Mode = "action"
		for _, name := range []string{"codex", "claudecode", "opencode"} {
			if got := cfg.EffectiveHookFailModeForConnector(name); got != tc.want {
				t.Errorf("profile %q %s: unset fail mode = %q, want %q", tc.profile, name, got, tc.want)
			}
		}
	}
}
