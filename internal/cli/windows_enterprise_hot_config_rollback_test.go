// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// payloadlessRollbackHost stages the nested ensure that `enterprise bundle
// apply` (the installed CLI, no payload) runs to put the last good config
// back: no bundle run, no binary sources.
func payloadlessRollbackHost(t *testing.T, bundleConfig, lastGood string) (*hotConfigHost, *windowsEnterpriseLifecycleOptions) {
	t.Helper()
	host, opts := newHotConfigHost(t, bundleConfig, lastGood)
	opts.gatewayBinary, opts.acpBinary, opts.hookBinary, opts.sensorHelperBinary, opts.policyCompiler = "", "", "", "", ""
	opts.bundle, opts.bundleRollback = nil, true
	savedDigest := windowsEnterprisePolicyDigest
	t.Cleanup(func() { windowsEnterprisePolicyDigest = savedDigest })
	windowsEnterprisePolicyDigest = host.digest
	return host, opts
}

// A payload-less rollback that restarted the gateway for a start-only key
// and then failed puts the refused bundle config back; the gateway must be
// restarted again so it does not keep running the rolled-back start-only
// settings while config.yaml holds the other ones.
func TestWindowsPayloadlessRollbackRestartsTheGatewayAfterUndo(t *testing.T) {
	const bundleConfig = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 500\n"
	const lastGood = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n"
	const lastGoodEnrolled = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n" +
		"enterprise:\n  enrollment:\n    include_users:\n      - alice\n"
	failedVerify := installedStatus("Verify")
	failedVerify["ok"], failedVerify["gateway_ready"] = false, false
	for _, tc := range []struct {
		name, lastGood, code string
		adopted              bool
		refreshFails         bool
		verify               []map[string]any
	}{
		{name: "not adopted", lastGood: lastGood, code: "bundle_policy_not_adopted"},
		{name: "targets refresh failed", lastGood: lastGoodEnrolled, code: "bundle_targets_refresh_failed", adopted: true, refreshFails: true},
		{name: "post-verify failed", lastGood: lastGood, code: "bundle_post_verify_failed", adopted: true, verify: []map[string]any{failedVerify}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, opts := payloadlessRollbackHost(t, bundleConfig, tc.lastGood)
			host.adopted = tc.adopted
			if tc.refreshFails {
				windowsEnterpriseHotConfigRefreshTargets = func(context.Context, managed.StandaloneLayout) error {
					return errors.New("enumerator refused")
				}
			}
			stub := &ensureStub{t: t, replies: tc.verify}
			stub.install(t)
			windowsEnterprisePolicyDigest = host.digest
			savedRestart, savedRecover := windowsEnterpriseHotConfigRestart, windowsEnterpriseHotConfigRecover
			t.Cleanup(func() {
				windowsEnterpriseHotConfigRestart, windowsEnterpriseHotConfigRecover = savedRestart, savedRecover
			})
			restarts, recovers := 0, 0
			windowsEnterpriseHotConfigRestart = func() (bool, error) { restarts++; return true, nil }
			windowsEnterpriseHotConfigRecover = func() (bool, error) { recovers++; return true, nil }
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
				&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
			installed, _ := os.ReadFile(host.configPath)
			if applied || string(installed) != bundleConfig || !windowsBundleHasCode(result.Errors, tc.code) {
				t.Fatalf("applied=%t installed=%q errors=%+v", applied, installed, result.Errors)
			}
			if restarts != 2 || recovers != 0 {
				t.Fatalf("restarts=%d recovers=%d, want the apply restart and one after undo", restarts, recovers)
			}
		})
	}
}

// A policy-only payload-less rollback asks the gateway to reload, as a
// policy-only bundle does: the file watcher is best effort on Windows, and a
// missed notification left the refused bundle policy enforcing.
func TestWindowsPayloadlessRollbackRequestsReloadForPolicyOnlyChange(t *testing.T) {
	const bundleConfig = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 500\n"
	const lastGood = "config_version: 9\nguardrail:\n  block_at: HIGH\n  hook_self_heal_debounce_ms: 500\n"
	host, opts := payloadlessRollbackHost(t, bundleConfig, lastGood)
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("Verify")}}
	stub.install(t)
	windowsEnterprisePolicyDigest = host.digest
	savedRestart := windowsEnterpriseHotConfigRestart
	t.Cleanup(func() { windowsEnterpriseHotConfigRestart = savedRestart })
	restarts := 0
	windowsEnterpriseHotConfigRestart = func() (bool, error) { restarts++; return true, nil }
	reloads := 0
	// The watcher misses the write: only the reload request gets the gateway
	// onto the last good policy.
	windowsEnterpriseHotBundleReload = func(context.Context, managed.StandaloneLayout) error {
		reloads++
		host.adopted = true
		return nil
	}
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
	installed, _ := os.ReadFile(host.configPath)
	if !applied || reloads != 1 || restarts != 0 || string(installed) != lastGood {
		t.Fatalf("applied=%t reloads=%d restarts=%d installed=%q errors=%+v", applied, reloads, restarts, installed, result.Errors)
	}

	// A failed reload request still waits for the watcher and the adoption
	// check, and says so.
	host, opts = payloadlessRollbackHost(t, bundleConfig, lastGood)
	host.adopted = true
	stub = &ensureStub{t: t, replies: []map[string]any{installedStatus("Verify")}}
	stub.install(t)
	windowsEnterprisePolicyDigest = host.digest
	windowsEnterpriseHotBundleReload = func(context.Context, managed.StandaloneLayout) error { return errors.New("pipe busy") }
	result = newWindowsEnterpriseStandaloneResult("ensure", opts)
	applied, _ = windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
	if !applied || !windowsBundleHasCode(result.Warnings, "bundle_reload_request_failed") {
		t.Fatalf("failed reload request: applied=%t warnings=%+v errors=%+v", applied, result.Warnings, result.Errors)
	}
}
