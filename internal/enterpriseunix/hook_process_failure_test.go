// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestManagedCodexStatusAndVerifyShowHookProcessFailure(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: machinePolicyConfig(t, h, "codex")}))
	for _, action := range []string{ActionStatus, ActionVerify, ActionEnsure} {
		r := h.run(Options{Action: action})
		message := messagesOf(r.Warnings, "hook_process_fail_open")
		if !strings.Contains(message, "codex") || !strings.Contains(message, "timeout") || r.SecurityComplete {
			t.Fatalf("%s warning=%q security_complete=%v", action, message, r.SecurityComplete)
		}
	}
}

// Install, ensure, repair and upgrade name the same hook-process limit as
// status and verify and never claim security_complete for it (ensure on a
// healthy macOS host with Codex enabled reported true while status and verify
// reported false). They still print no connectors block.
func TestManagedCodexLifecycleChangesShowHookProcessFailure(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			results := map[string]*enterprisestatus.Result{
				ActionInstall: h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: machinePolicyConfig(t, h, "codex")}),
			}
			h.publishLedger([]byte("ledger\n"))
			results[ActionEnsure] = h.run(Options{Action: ActionEnsure})
			results[ActionRepair] = h.run(Options{Action: ActionRepair})
			results[ActionUpgrade] = h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.5")})
			results[ActionStatus] = h.run(Options{Action: ActionStatus})
			results[ActionVerify] = h.run(Options{Action: ActionVerify})
			for action, r := range results {
				requireOK(t, r)
				message := messagesOf(r.Warnings, "hook_process_fail_open")
				if !strings.Contains(message, "codex") || r.SecurityComplete {
					t.Fatalf("%s %s: warning=%q security_complete=%v", goos, action, message, r.SecurityComplete)
				}
				if published := r.Connectors != nil; published != (action == ActionStatus || action == ActionVerify) {
					t.Fatalf("%s %s: connectors block published=%v", goos, action, published)
				}
			}
		})
	}
}
