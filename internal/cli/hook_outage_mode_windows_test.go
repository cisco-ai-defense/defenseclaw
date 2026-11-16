// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"path/filepath"
	"testing"
)

// oss-outage-open review (loop round 3): the packaged Windows launcher's
// outage mode comes from the config of its protected install-state data
// root. The agent's DEFENSECLAW_CONFIG and DEFENSECLAW_HOME, which name
// another default-tier config, neither reopen a strict outage nor close a
// default one.
func TestPackagedWindowsHookOutageReadsTheInstalledRuntimesConfig(t *testing.T) {
	for _, tc := range []struct {
		name, installed, agent, want string
	}{
		{"strict install, default config named by the agent", outageNowStrictConfig, outageNowDefaultConfig, "closed"},
		{"default install, strict config named by the agent", outageNowDefaultConfig, outageNowStrictConfig, "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, trustedHome := stageTrustedNativeHookForTest(t, "open")
			writeOutageNowConfig(t, trustedHome, tc.installed)
			attacker := filepath.Join(t.TempDir(), "attacker-home")
			writeOutageNowConfig(t, attacker, tc.agent)
			t.Setenv("DEFENSECLAW_HOME", attacker)
			t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(attacker, "config.yaml"))

			opts := buildHookOptions("claudecode", "PreToolUse", "", "")
			if opts.Home != trustedHome || opts.OutageFailModeNow == nil {
				t.Fatalf("the packaged hook did not take its installed runtime: %+v", opts)
			}
			if got := opts.OutageFailModeNow(); got != tc.want {
				t.Fatalf("outage mode now = %q, want %q", got, tc.want)
			}
		})
	}
}
