// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"
)

// A recovered config generation record does not replace ensure's plan. Every
// plan the planner selects for an installed deployment is kept: a newer
// Setup over 1.0.2 upgrades (a forced repair put the newer binaries in place
// and recorded 1.0.2), drift is reapplied and a pending transaction is
// recovered. Only a compliant deployment becomes the repair that restarts
// the gateway on the recovered record, and a refusal stays a refusal.
func TestWindowsEnterpriseGenerationRecoveryKeepsThePlannedAction(t *testing.T) {
	refused := errors.New("downgrade_refused: installed version 1.0.5 is newer than 1.0.4")
	for _, tc := range []struct {
		name    string
		planned windowsEnterpriseEnsurePlan
		err     error
		want    windowsEnterpriseEnsurePlan
	}{
		{"1.0.2 to 1.0.4 upgrade", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:1.0.2"}, nil,
			windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:1.0.2"}},
		{"0.8.10 to 1.0.4 upgrade", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:0.8.10"}, nil,
			windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:0.8.10"}},
		{"binary drift", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:gateway"}, nil,
			windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:gateway"}},
		{"manifest drift", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:manifest"}, nil,
			windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:manifest"}},
		{"bundle drift", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:bundle"}, nil,
			windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:bundle"}},
		{"pending transaction", windowsEnterpriseEnsurePlan{Action: "repair", Reason: "transaction_pending"}, nil,
			windowsEnterpriseEnsurePlan{Action: "repair", Reason: "transaction_pending"}},
		{"compliant", windowsEnterpriseEnsurePlan{Reason: "compliant"}, nil,
			windowsEnterpriseEnsurePlan{Action: "repair", Reason: "verify_failed", Detail: windowsEnterpriseGenerationRecoveryDetail}},
		{"refusal", windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "ignored"}, refused, windowsEnterpriseEnsurePlan{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, err := planWindowsEnterpriseEnsureAfterGenerationRecovery(func() (windowsEnterpriseEnsurePlan, error) {
				calls++
				return tc.planned, tc.err
			})
			if calls != 1 {
				t.Fatalf("planner ran %d times, want once", calls)
			}
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Fatalf("plan = %+v, %v; want %+v, %v", got, err, tc.want, tc.err)
			}
		})
	}
}

// GAP-0044: a config-only change on the installed release that ran the
// lifecycle transaction (a machine policy key, the Cowork VM sensor, the
// Codex target, a manifest, a change the running gateway did not take)
// reports ensure_config_restart and says no upgrade happened; a real
// upgrade, a payload reinstall and a repair keep ensure_<action>.
func TestWindowsEnterpriseEnsureActionWarningNamesAConfigChange(t *testing.T) {
	for _, tc := range []struct {
		name     string
		plan     windowsEnterpriseEnsurePlan
		version  string
		keys     []string
		codex    bool
		failed   bool
		code     string
		contains []string
		absent   []string
	}{
		{name: "machine policy key", plan: windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:config"}, version: "1.0.8",
			keys: []string{"enterprise.machine_policy.default.managed_hooks_only"}, code: "ensure_config_restart",
			contains: []string{"configuration change (drift:config) to the installed release 1.0.8 and upgraded nothing",
				"the services read enterprise.machine_policy.default.managed_hooks_only only at start",
				"stops and starts every service", "two to six minutes"},
			absent: []string{"ensure ran upgrade"}},
		{name: "cowork sensor key", plan: windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:config"}, version: "1.0.8",
			keys: []string{"enterprise.cowork_vm_sensor.enabled"}, code: "ensure_config_restart",
			contains: []string{"enterprise.cowork_vm_sensor.enabled only at start"}},
		{name: "change the running gateway did not take", plan: windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:config"}, version: "1.0.8",
			code: "ensure_config_restart", contains: []string{"could not be applied in the running deployment"}},
		{name: "codex target", plan: windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:codex_target"}, version: "1.0.8", codex: true,
			code: "ensure_config_restart", contains: []string{"Codex's machine policy, so ensure ran the lifecycle transaction"}},
		{name: "bundle on a staged deployment", plan: windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:bundle"},
			code: "ensure_config_restart", contains: []string{"to the installed release and upgraded nothing"}},
		{name: "manifest", plan: windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:manifest"}, version: "1.0.8",
			code: "ensure_config_restart", contains: []string{"guardian manifest"}},
		// GAP-0044 review: a failed or rolled-back transaction applied
		// nothing it can confirm, and its warning is not a repair.
		{name: "failed config transaction", plan: windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:config"}, version: "1.0.8",
			keys: []string{"enterprise.machine_policy.default.managed_hooks_only"}, failed: true, code: "ensure_config_failed",
			contains: []string{"ensure ran the lifecycle transaction for a configuration change (drift:config) on the installed release 1.0.8 and upgraded nothing",
				"did not succeed", "not confirmed applied"},
			absent: []string{"ensure applied", "verifies the deployment", "ensure ran upgrade"}},
		{name: "failed manifest transaction", plan: windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:manifest"}, failed: true,
			code: "ensure_config_failed", contains: []string{"(drift:manifest) on the installed release and upgraded nothing"}, absent: []string{"ensure applied"}},
		{name: "failed real upgrade keeps its action", plan: windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:1.0.7"}, version: "1.0.7", failed: true,
			code: "ensure_upgrade", contains: []string{"ensure ran upgrade: older_version:1.0.7"}},
		{name: "real upgrade", plan: windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:1.0.7"}, version: "1.0.7",
			code: "ensure_upgrade", contains: []string{"ensure ran upgrade: older_version:1.0.7"}, absent: []string{"configuration change"}},
		{name: "payload reinstall", plan: windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:gateway"}, version: "1.0.8",
			code: "ensure_upgrade", contains: []string{"ensure ran upgrade: drift:gateway"}},
		{name: "codex repair without a payload", plan: windowsEnterpriseEnsurePlan{Action: "repair", Reason: "drift:config"}, codex: true,
			code: "ensure_repair", contains: []string{"ensure ran repair: drift:config (the config turns Codex protection", ", so every service was restarted)"}},
		{name: "cowork drift repair", plan: windowsEnterpriseEnsurePlan{Action: "repair", Reason: "drift:cowork_vm_sensor", Detail: "not ready"},
			code: "ensure_repair", contains: []string{"ensure ran repair: drift:cowork_vm_sensor: not ready"}},
		{name: "install", plan: windowsEnterpriseEnsurePlan{Action: "install", Reason: "not_installed"},
			code: "ensure_install", contains: []string{"ensure ran install: not_installed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, message := windowsEnterpriseEnsureActionWarning(tc.plan, tc.version, tc.keys, tc.codex, !tc.failed)
			if code != tc.code {
				t.Fatalf("code %q, want %q (message %q)", code, tc.code, message)
			}
			for _, want := range tc.contains {
				if !strings.Contains(message, want) {
					t.Errorf("message %q lacks %q", message, want)
				}
			}
			for _, unwanted := range tc.absent {
				if strings.Contains(message, unwanted) {
					t.Errorf("message %q has %q", message, unwanted)
				}
			}
		})
	}
}
