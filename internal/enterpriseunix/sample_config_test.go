// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// sampleConfigs are the standalone configs the enterprise docs publish for
// Linux and macOS (testdata/enterprise-configs); the docs show them byte for
// byte.
var sampleConfigs = []struct{ goos, file string }{
	{"linux", "linux-standalone.yaml"},
	{"darwin", "macos-standalone.yaml"},
}

func readSampleConfig(t *testing.T, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "enterprise-configs", file))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// requireNoHostInstall skips on a host with a real standalone install for
// layout: config validation inspects the real data directory and the real
// administrator rule pack, while this harness installs into a temporary
// root.
func requireNoHostInstall(t *testing.T, layout managed.StandaloneLayout) {
	t.Helper()
	for _, dir := range []string{layout.DataDir, filepath.Join(layout.PolicyDir, "guardrail", "default")} {
		if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Skipf("%s is present or unreadable on this host; the rooted lifecycle harness cannot model it", dir)
		}
	}
}

func writeTempConfig(t *testing.T, raw []byte) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Every published sample installs as written, and a following ensure
// accepts it. The samples leave rule_pack_dir unset and point policy_dir at
// the administrator folder, which holds no rule pack on a fresh host, so the
// implicit pack must resolve to the vendor default pack.
func TestPublishedSampleConfigsInstall(t *testing.T) {
	for _, sample := range sampleConfigs {
		t.Run(sample.goos, func(t *testing.T) {
			raw := readSampleConfig(t, sample.file)
			h := newTestHost(t, sample.goos)
			requireNoHostInstall(t, h.env.Layout)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, raw)}))
			if got := h.read(h.env.Layout.ConfigPath); got != string(raw) {
				t.Fatalf("installed config differs from the sample:\n%s", got)
			}
			requireOK(t, h.run(Options{Action: ActionEnsure}))
			validated, err := h.env.validateConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			vendor := path.Join(h.env.Layout.VendorPolicyDir, "guardrail", "default")
			if got := validated.Loaded.Guardrail.RulePackDir; got != vendor {
				t.Fatalf("rule_pack_dir = %q, want the vendor pack %q", got, vendor)
			}
			if got := validated.Connectors; len(got) != 2 {
				t.Fatalf("enabled connectors = %v, want the sample's two", got)
			}
		})
	}
}

// previousDefaultConfig is the config earlier builds wrote when the
// administrator supplied none (policy_dir at the administrator folder, no
// rule_pack_dir). Hosts installed then keep it across upgrades.
func previousDefaultConfig(layout managed.StandaloneLayout) []byte {
	return []byte(fmt.Sprintf(`# DefenseClaw managed enterprise configuration (standalone profile).
# Administrator-owned. Edit through your MDM or configuration management;
# the lifecycle validates and applies every change.
config_version: 8
deployment_mode: managed_enterprise
data_dir: %s
policy_dir: %s
enterprise:
  profile: standalone
gateway:
  api_bind: 127.0.0.1
  api_port: 18970
guardrail:
  enabled: true
  mode: observe
`, layout.DataDir, layout.PolicyDir))
}

// ensure keeps working on a host whose config an earlier build wrote: the
// config_version 8 file is installed as its v9 migration, with the v8 bytes,
// migration-v9.json and a lifecycle config generation next to it, and an
// inline VirusTotal key moves to the service .env.
func TestEnsureAcceptsThePreviousDefaultConfig(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireNoHostInstall(t, h.env.Layout)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			previous := append(previousDefaultConfig(h.env.Layout),
				"scanners:\n  skill_scanner:\n    use_virustotal: true\n    virustotal_api_key: vt-test-value\n"...)
			if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), previous, 0o644); err != nil {
				t.Fatal(err)
			}
			r := h.run(Options{Action: ActionEnsure})
			requireOK(t, r)
			if r.Noop {
				t.Fatal("the changed config must be applied")
			}
			record, err := h.env.loadDeployment()
			if err != nil {
				t.Fatal(err)
			}
			installed := h.read(h.env.Layout.ConfigPath)
			if config.NeedsMigrationV9([]byte(installed)) || !strings.Contains(installed, "config_version: 9") {
				t.Fatalf("installed config is not config_version 9:\n%s", installed)
			}
			if record.ConfigSHA256 != sha256Bytes([]byte(installed)) {
				t.Fatal("record does not reflect the installed config")
			}
			if got := h.read(h.env.Layout.ConfigPath + config.ConfigV8BackupSuffix); got != string(previous) {
				t.Fatal("config.yaml.v8.bak does not hold the previous config")
			}
			if _, err := os.Stat(h.env.P(config.MigrationRecordPath(h.env.Layout.ConfigPath))); err != nil {
				t.Fatalf("migration-v9.json: %v", err)
			}
			if env := h.read(serviceDotEnvPath(h.env)); !strings.Contains(env, "VIRUSTOTAL_API_KEY=vt-test-value") {
				t.Fatal("the inline VirusTotal key is not in the service .env")
			}
			state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
			if err != nil || state.Actor != configwrite.ActorLifecycle || state.ConfigSHA256 != record.ConfigSHA256 {
				t.Fatalf("config generation = %+v (%v), want the lifecycle's record of the installed config", state, err)
			}
		})
	}
}

// After a rollback an earlier release records its own version and the v8
// config it was given. Upgrading again migrates that config again, instead of
// treating it as a v8 file configuration management put back and leaving the
// old migration-v9.json as the only record (GAP-0113).
func TestReUpgradeAfterARollbackMigratesTheConfigAgain(t *testing.T) {
	h := newTestHost(t, "linux")
	requireNoHostInstall(t, h.env.Layout)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	previous := previousDefaultConfig(h.env.Layout)
	configPath := h.env.P(h.env.Layout.ConfigPath)
	if err := os.WriteFile(configPath, previous, 0o644); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	if config.NeedsMigrationV9([]byte(h.read(h.env.Layout.ConfigPath))) {
		t.Fatal("premise: the first upgrade migrates the v8 config")
	}
	// The rollback put the v8 bytes back and recorded the older release.
	if err := os.WriteFile(configPath, previous, 0o644); err != nil {
		t.Fatal(err)
	}
	record, err := h.env.loadDeployment()
	if err != nil {
		t.Fatal(err)
	}
	record.ProductVersion, record.ConfigSHA256 = "0.9.0", sha256Bytes(previous)
	if err := h.env.saveDeployment(record); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	if installed := h.read(h.env.Layout.ConfigPath); config.NeedsMigrationV9([]byte(installed)) {
		t.Fatalf("the re-upgrade left the config at config_version 8:\n%s", installed)
	}
	if h.read(h.env.Layout.ConfigPath+config.ConfigV8BackupSuffix) != string(previous) {
		t.Fatal("config.yaml.v8.bak does not hold the config the re-upgrade migrated")
	}
}

// The layout fixes data_dir and ships the default rule pack, so a config may
// leave data_dir, policy_dir and rule_pack_dir out. An explicit wrong value
// is still refused before any change.
func TestLayoutFixedKeysMayBeOmitted(t *testing.T) {
	const minimal = `config_version: 8
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
guardrail:
  enabled: true
  mode: observe
  connectors:
    codex: {}
`
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireNoHostInstall(t, h.env.Layout)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(minimal))}))
			validated, err := h.env.validateConfig([]byte(minimal))
			if err != nil {
				t.Fatal(err)
			}
			if got := validated.Loaded.DataDir; got != h.env.Layout.DataDir {
				t.Fatalf("data_dir = %q, want %q", got, h.env.Layout.DataDir)
			}
			if got, want := validated.Loaded.Guardrail.RulePackDir, path.Join(h.env.Layout.VendorPolicyDir, "guardrail", "default"); got != want {
				t.Fatalf("rule_pack_dir = %q, want %q", got, want)
			}
		})
		t.Run(goos+"/explicit values are still checked", func(t *testing.T) {
			layout, err := managed.StandaloneLayoutFor(goos)
			if err != nil {
				t.Fatal(err)
			}
			requireNoHostInstall(t, layout)
			for want, extra := range map[string]string{
				"data_dir":        "data_dir: " + layout.ConfigDir + "\n",
				"inside data_dir": "data_dir: " + layout.DataDir + "\npolicy_dir: " + layout.DataDir + "/policies\n",
			} {
				h := newTestHost(t, goos)
				raw := "config_version: 8\n" + extra + minimal[len("config_version: 8\n"):]
				if want == "inside data_dir" {
					raw += "  rule_pack_dir: " + layout.DataDir + "/policies/guardrail/default\n"
				}
				r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(raw))})
				requireError(t, r, codeConfig)
				if len(r.Errors) == 0 || !strings.Contains(r.Errors[0].Message, want) {
					t.Fatalf("errors = %+v, want %q", r.Errors, want)
				}
			}
		})
	}
}

// An unset rule_pack_dir follows <policy_dir>/guardrail/default once the
// administrator creates that folder. The config bytes do not change, so the
// record keeps the resolved pack: the next ensure applies the new pack and
// restarts the gateway instead of reporting up_to_date while the gateway
// keeps the vendor pack.
func TestEnsureAppliesANewlyCreatedImplicitRulePack(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireNoHostInstall(t, h.env.Layout)
			// A policy_dir this test can create a pack in: the loader looks at
			// the host path, the lifecycle at the path under its root.
			policyDir := t.TempDir()
			raw := fmt.Sprintf("config_version: 8\ndeployment_mode: managed_enterprise\ndata_dir: %s\npolicy_dir: %s\n"+
				"enterprise:\n  profile: standalone\nguardrail:\n  enabled: true\n  mode: observe\n  connectors:\n    codex: {}\n",
				h.env.Layout.DataDir, policyDir)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(raw))}))
			vendor := path.Join(h.env.Layout.VendorPolicyDir, "guardrail", "default")
			record, err := h.env.loadDeployment()
			if err != nil {
				t.Fatal(err)
			}
			if got := record.RulePacks["guardrail.rule_pack_dir"]; got != vendor {
				t.Fatalf("recorded rule pack = %q, want the vendor pack %q", got, vendor)
			}
			if r := h.run(Options{Action: ActionEnsure}); !r.Noop {
				t.Fatalf("premise: an unchanged deployment is up to date: %+v", r)
			}

			pack := filepath.Join(policyDir, "guardrail", "default")
			for _, dir := range []string{pack, h.env.P(pack)} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			gateway := unitGateway
			if goos == "darwin" {
				gateway = labelGateway
			}
			before := len(h.services.calls)
			r := h.run(Options{Action: ActionEnsure})
			requireOK(t, r)
			if r.Noop {
				t.Fatal("ensure reported up to date after the implicit rule pack changed")
			}
			restarted := false
			for _, call := range h.services.calls[before:] {
				if call == "stop "+gateway {
					restarted = true
				}
			}
			if !restarted {
				t.Fatalf("the gateway was not restarted to load the new pack: %v", h.services.calls[before:])
			}
			if record, err = h.env.loadDeployment(); err != nil {
				t.Fatal(err)
			}
			if got := record.RulePacks["guardrail.rule_pack_dir"]; got != pack {
				t.Fatalf("recorded rule pack = %q, want the administrator pack %q", got, pack)
			}
			if r := h.run(Options{Action: ActionEnsure}); !r.Noop {
				t.Fatalf("ensure did not converge after applying the pack: %+v", r)
			}
		})
	}
}
