// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"strings"
	"testing"
)

func TestWindowsEnterpriseAllConnectorModesDefaultOpen(t *testing.T) {
	for _, name := range []string{"amp", "claudecode", "codex", "cursor", "copilot", "geminicli", "antigravity", "hermes", "windsurf", "openhands", "opencode"} {
		for _, configured := range []string{"", "open", "closed"} {
			if mode := windowsEnterpriseHookFailMode(name, configured); mode != "open" {
				t.Errorf("connector=%s configured=%q mode=%q, want open", name, configured, mode)
			}
		}
	}
}

func TestWindowsManagedRuntimeBundleOpenDefaultAndLegacyUpgrade(t *testing.T) {
	for _, name := range []string{"claudecode", "codex", "cursor"} {
		t.Run(name, func(t *testing.T) {
			desired := WindowsManagedRuntimeGenerationDesired{
				Connector:                  name,
				TargetSID:                  "S-1-5-21-1000-1000-1000-1001",
				DataDir:                    `C:\Users\developer\.defenseclaw`,
				HookExecutable:             `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`,
				GatewayAddr:                "127.0.0.1:18970",
				GatewayServiceName:         "DefenseClawGateway-Test",
				ScopedToken:                "scoped-" + name + "-token",
				HookContractID:             name + "-hooks-v1",
				HookContractLockUpdatedAt:  "2026-08-24T10:00:03Z",
				HookContractEntryUpdatedAt: "2026-08-24T10:00:02Z",
			}
			generation := strings.Repeat("a", 32)
			bundle := windowsManagedRuntimeBundleFromDesired(desired, generation)
			selector := windowsManagedRuntimeSelectorTargetFromDesired(desired, generation, "")
			if bundle.FailMode != "open" || !windowsManagedRuntimeBundleMatchesDesired(bundle, desired) {
				t.Fatalf("new bundle must publish open: mode=%q", bundle.FailMode)
			}
			for _, mode := range []string{"open", "closed"} {
				bundle.FailMode = mode
				if err := validateWindowsManagedRuntimeBundleAgainstSelector(bundle, selector); err != nil {
					t.Fatalf("trusted %s bundle must remain readable during upgrade: %v", mode, err)
				}
				if mode == "closed" && windowsManagedRuntimeBundleMatchesDesired(bundle, desired) {
					t.Fatal("legacy closed bundle must be republished by repair")
				}
			}
			bundle.FailMode = "invalid"
			if err := validateWindowsManagedRuntimeBundleAgainstSelector(bundle, selector); err == nil {
				t.Fatal("invalid bundle mode accepted")
			}
		})
	}
}
