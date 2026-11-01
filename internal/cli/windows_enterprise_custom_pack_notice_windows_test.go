// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1076 (managed): Setup /ensure applied an admin config whose custom pack,
// selected by no setting, pins a digest that does not match its files, with
// only ensure_config_applied. The change actions now warn
// custom_pack_will_not_load naming the key and the files digest; a matching
// pin and the read-only actions say nothing.
func TestWindowsEnterpriseLifecycleWarnsAnUnselectedCustomPackThatWillNotLoad(t *testing.T) {
	configDir := t.TempDir()
	pack := filepath.Join(configDir, "packs", "acme")
	if err := os.MkdirAll(pack, 0o700); err != nil {
		t.Fatal(err)
	}
	suppressions := "version: 1\r\npre_judge_strips: []\r\nfinding_suppressions: []\r\ntool_suppressions: []\r\n"
	if err := os.WriteFile(filepath.Join(pack, "suppressions.yaml"), []byte(suppressions), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := guardrail.LoadRulePack(pack)
	if err != nil {
		t.Fatal(err)
	}
	filesDigest := "sha256:" + loaded.FilesDigest()
	configPath := filepath.Join(configDir, "config.yaml")
	writeConfig := func(pin string) {
		t.Helper()
		body := strings.Replace(strings.Replace(standaloneGatewayCheckConfig, "config_version: 8\n", "config_version: 9\n", 1),
			`  rule_pack_dir: ""`, "  custom_packs:\n    acme:\n      path: '"+pack+"'\n      digest: "+pin, 1)
		if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previousLayout, previousDigest := windowsEnterpriseHotConfigLayout, windowsEnterprisePolicyDigest
	t.Cleanup(func() {
		windowsEnterpriseHotConfigLayout, windowsEnterprisePolicyDigest = previousLayout, previousDigest
	})
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: configPath, ConfigDir: configDir, DataDir: t.TempDir()}, nil
	}
	windowsEnterprisePolicyDigest = func(context.Context) ([]byte, error) {
		return []byte(`{"effective_digest":"sha256:aa","config_generation":6,"config_generation_recorded":true,"gateway_reported_digest":"sha256:aa"}`), nil
	}
	run := func(action string) *enterprisestatus.Result {
		result := newWindowsEnterpriseStandaloneResult(action, &windowsEnterpriseLifecycleOptions{})
		result.Installed, result.Readiness.Gateway = true, true
		applyWindowsEnterprisePolicy(context.Background(), result)
		return result
	}
	notice := func(result *enterprisestatus.Result) string {
		for _, warning := range result.Warnings {
			if warning.Code == "custom_pack_will_not_load" {
				return warning.Message
			}
		}
		return ""
	}

	writeConfig("sha256:" + strings.Repeat("0", 64))
	for _, action := range []string{"ensure", "repair", "upgrade"} {
		got := notice(run(action))
		for _, want := range []string{"guardrail.custom_packs.acme is registered but will not load", filesDigest, "guardrail.custom_packs.acme.digest"} {
			if !strings.Contains(got, want) {
				t.Fatalf("%s: custom_pack_will_not_load = %q, want it to name %q", action, got, want)
			}
		}
	}
	for _, action := range []string{"status", "verify"} {
		if got := notice(run(action)); got != "" {
			t.Fatalf("%s warned %q", action, got)
		}
	}
	writeConfig(filesDigest)
	if got := notice(run("ensure")); got != "" {
		t.Fatalf("a matching pin warned %q", got)
	}
}
