// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsHotBundlePostVerifyReportsFailureAndRestoresConfig(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	const next = "config_version: 9\nguardrail:\n  block_at: LOW\n"
	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	opts.bundle = host.bundleRun()
	savedDigest := windowsEnterprisePolicyDigest
	t.Cleanup(func() { windowsEnterprisePolicyDigest = savedDigest })
	verify := installedStatus("Verify")
	verify["ok"] = false
	verify["errors"] = []string{"guardian protected target coverage is not verified"}
	stub := &ensureStub{t: t, replies: []map[string]any{verify}}
	stub.install(t)
	windowsEnterprisePolicyDigest = host.digest
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
	got, err := os.ReadFile(host.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if applied || string(got) != previous || len(host.writes) != 1 {
		t.Fatalf("applied=%t config=%q writes=%q", applied, got, host.writes)
	}
	if len(result.Errors) != 1 || result.Errors[0].Code != "bundle_post_verify_failed" ||
		!strings.Contains(result.Errors[0].Message, "guardian protected target coverage is not verified") {
		t.Fatalf("post-verify error = %+v", result.Errors)
	}
}

func TestWindowsHotBundleReloadFailureCanStillConfirmWatcherAdoption(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	const next = "config_version: 9\nguardrail:\n  block_at: LOW\n"
	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	opts.bundle = host.bundleRun()
	savedDigest := windowsEnterprisePolicyDigest
	t.Cleanup(func() { windowsEnterprisePolicyDigest = savedDigest })
	windowsEnterpriseHotBundleReload = func(context.Context, managed.StandaloneLayout) error {
		return errors.New("HTTP 500: observability metric failed")
	}
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("Verify")}}
	stub.install(t)
	windowsEnterprisePolicyDigest = host.digest
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
	if !applied || len(host.writes) != 1 || len(result.Errors) != 0 {
		t.Fatalf("applied=%t writes=%q errors=%v", applied, host.writes, result.Errors)
	}
	found := false
	for _, warning := range result.Warnings {
		if warning.Code == "bundle_reload_request_failed" && strings.Contains(warning.Message, "HTTP 500: observability metric failed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("reload warning with cause missing: %+v", result.Warnings)
	}
}
