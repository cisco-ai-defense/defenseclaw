// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A managed standalone config read from the Linux or macOS layout path may
// leave out the settings the layout fixes: data_dir defaults to the layout's
// data directory (the services and the lifecycle accept only that one) and
// the rule pack to the vendor default pack. Explicit values are kept as
// written so the lifecycle can refuse a wrong one.
func TestStandaloneLayoutConfigDefaultsLayoutFixedPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Linux and macOS layout paths are not paths on Windows")
	}
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
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
		layout, err := managed.StandaloneLayoutFor(goos)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(goos, func(t *testing.T) {
			cfg, err := LoadRuntimeV8InspectionCandidateFromBytes(layout.ConfigPath, []byte(minimal))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.DataDir != layout.DataDir {
				t.Fatalf("data_dir = %q, want the layout's %q", cfg.DataDir, layout.DataDir)
			}
			if want := layout.VendorPolicyDir + "/guardrail/default"; cfg.Guardrail.RulePackDir != want {
				t.Fatalf("rule_pack_dir = %q, want the vendor pack %q", cfg.Guardrail.RulePackDir, want)
			}
			if want := layout.VendorPolicyDir + "/guardrail/default"; cfg.EffectiveRulePackDirForConnector("codex") != want {
				t.Fatalf("codex rule pack = %q, want %q", cfg.EffectiveRulePackDirForConnector("codex"), want)
			}
			// The gateway loads its Rego from policy_dir: it stays out of
			// the service-writable data_dir.
			if cfg.PolicyDir != layout.VendorPolicyDir {
				t.Fatalf("policy_dir = %q, want the vendor policy folder %q", cfg.PolicyDir, layout.VendorPolicyDir)
			}
			for label, value := range map[string]string{
				"audit_db":                cfg.AuditDB,
				"plugin_dir":              cfg.PluginDir,
				"gateway.device_key_file": cfg.Gateway.DeviceKeyFile,
			} {
				if !strings.HasPrefix(value, layout.DataDir+"/") {
					t.Errorf("%s = %q, want a path under %s", label, value, layout.DataDir)
				}
			}
			// The compile inspects the local store paths, so on a host where
			// this layout is really installed (its data directory exists and
			// is private to the service) only the loader is checked.
			if _, err := os.Lstat(layout.DataDir); errors.Is(err, fs.ErrNotExist) {
				compiled, err := ParseCompileObservabilityV8(layout.ConfigPath, []byte(minimal), ObservabilityV8CompileOptions{DefaultDataDir: filepath.Join(t.TempDir(), "elsewhere")})
				if err != nil {
					t.Fatal(err)
				}
				if compiled.DataDir != layout.DataDir {
					t.Fatalf("compiled data_dir = %q, want %q", compiled.DataDir, layout.DataDir)
				}
				if local := compiled.Plan.Snapshot().Local.Path; !strings.HasPrefix(local, layout.DataDir+"/") {
					t.Fatalf("compiled local store %q is not under %s", local, layout.DataDir)
				}
			} else {
				t.Logf("%s exists on this host; compile check skipped", layout.DataDir)
			}

			explicit := strings.Replace(minimal, "deployment_mode: managed_enterprise\n", "deployment_mode: managed_enterprise\ndata_dir: "+layout.ConfigDir+"\n", 1)
			cfg, err = LoadRuntimeV8InspectionCandidateFromBytes(layout.ConfigPath, []byte(explicit))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.DataDir != layout.ConfigDir {
				t.Fatalf("an explicit data_dir must be kept for the lifecycle to refuse: got %q", cfg.DataDir)
			}
		})
	}

	linux, err := managed.StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("unmanaged config at the layout path", func(t *testing.T) {
		cfg, err := LoadRuntimeV8InspectionCandidateFromBytes(linux.ConfigPath, []byte("config_version: 8\nguardrail:\n  enabled: true\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DataDir != linux.ConfigDir {
			t.Fatalf("data_dir = %q, want the config folder %q", cfg.DataDir, linux.ConfigDir)
		}
	})
	t.Run("standalone config elsewhere", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		cfg, err := LoadRuntimeV8InspectionCandidateFromBytes(path, []byte(minimal))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DataDir != filepath.Dir(path) {
			t.Fatalf("data_dir = %q, want the config folder %q", cfg.DataDir, filepath.Dir(path))
		}
	})
	t.Run("secure client at the macOS layout path", func(t *testing.T) {
		darwin, err := managed.StandaloneLayoutFor("darwin")
		if err != nil {
			t.Fatal(err)
		}
		if dir, ok := standaloneLayoutDataDirForSource(darwin.ConfigPath, []byte("config_version: 8\ndeployment_mode: managed_enterprise\n")); ok {
			t.Fatalf("a Secure Client config got the standalone data_dir %q", dir)
		}
	})
}
