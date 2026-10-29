// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"slices"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// The bundle verify prediction and the Windows hot config path agree on
// every class of bundle config change: a policy-only change and an
// enrollment list or connector set change apply in the running gateway; a
// start-only key restarts the gateway alone; a Codex protection change runs
// the full transaction; a Fleet change is refused before any write.
func TestWindowsBundleRestartPredictionMatchesTheHotPath(t *testing.T) {
	const base = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 500\n  connectors:\n    claudecode:\n      enabled: true\n"
	for _, tc := range []struct {
		name, previous, next string
		want                 string
		reason               string
	}{
		{"policy only", base, "config_version: 9\nguardrail:\n  block_at: HIGH\n  hook_self_heal_debounce_ms: 500\n  connectors:\n    claudecode:\n      enabled: true\n", bundleRestartNotRequired, ""},
		{"enrollment list only", "config_version: 9\nenterprise:\n  enrollment:\n    exclude_users:\n      - alice\n" + base[len("config_version: 9\n"):],
			"config_version: 9\nenterprise:\n  enrollment:\n    exclude_users: []\n" + base[len("config_version: 9\n"):], bundleRestartNotRequired, ""},
		{"connector added", base, base + "    opencode:\n      enabled: true\n", bundleRestartNotRequired, ""},
		// A connector that sorts before the unset guardrail.connector's
		// first key moves the primary connector the gateway holds until a
		// restart (GAP-1498).
		{"connector added before the primary", base, base + "    amp:\n      enabled: true\n", bundleRestartRequired, restartReasonSettings},
		{"start-only key", base, "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n  connectors:\n    claudecode:\n      enabled: true\n", bundleRestartRequired, restartReasonSettings},
		{"Codex protection on", base, base + "    codex:\n      enabled: true\n", bundleRestartRequired, restartReasonCodexMachinePolicy},
		{"Fleet enabled", base, base + "fleet:\n  enabled: true\n", bundleRestartUnknown, restartReasonFleetSetup},
	} {
		t.Run(tc.name, func(t *testing.T) {
			predicted := predictBundleRestart("windows", configwrite.ManagedDefaults{}, []byte(tc.previous), nil, []byte(tc.next))
			if predicted.GatewayRestart != tc.want || (tc.reason != "" && !slices.Contains(predicted.ReasonCodes, tc.reason)) {
				t.Fatalf("prediction = %+v, want %s %s", predicted, tc.want, tc.reason)
			}

			host, opts := newHotConfigHost(t, tc.previous, tc.next)
			host.adopted = true
			opts.bundle = host.bundleRun()
			savedRestart, savedDigest := windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest
			savedProcesses, savedMetadata := windowsEnterpriseAgentProcesses, windowsEnterpriseActivationMetadata
			t.Cleanup(func() {
				windowsEnterpriseHotConfigRestart, windowsEnterprisePolicyDigest = savedRestart, savedDigest
				windowsEnterpriseAgentProcesses, windowsEnterpriseActivationMetadata = savedProcesses, savedMetadata
			})
			restarts := 0
			windowsEnterpriseHotConfigRestart = func() (bool, error) { restarts++; return true, nil }
			windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) { return nil, nil }
			windowsEnterpriseActivationMetadata = func() (string, bool) { return "", false }
			stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("Verify")}}
			stub.install(t)
			windowsEnterprisePolicyDigest = host.digest
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
				&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
			restarted := restarts > 0 || opts.codexTargetTransaction
			refused := windowsBundleHasCode(result.Errors, "fleet_setup_required")
			switch tc.want {
			case bundleRestartUnknown:
				if applied || !refused {
					t.Fatalf("hot path applied=%t errors=%v, prediction %+v", applied, result.Errors, predicted)
				}
			default:
				if restarted != (tc.want == bundleRestartRequired) || refused {
					t.Fatalf("hot path applied=%t restarts=%d transaction=%t errors=%v, prediction %+v",
						applied, restarts, opts.codexTargetTransaction, result.Errors, predicted)
				}
			}
		})
	}
}
