// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestModeOnlyReloadKeepsPreviousPackPostureForHookRefresh(t *testing.T) {
	for _, tc := range []struct{ before, after string }{
		{"default", "strict"},
		{"strict", "default"},
		{"default", "default"},
	} {
		t.Run(tc.before+"_to_"+tc.after, func(t *testing.T) {
			fixture := newSidecarV8BootstrapFixture(t, config.ConfigVersionV9, "")
			packDir := filepath.Join(fixture.dataDir, "policies", "guardrail", "default")
			t.Cleanup(func() { packPostures.Delete(packDir); pendingPackPostures.Delete(packDir) })
			manifest := filepath.Join(packDir, guardrail.PackManifestFile)
			writePosture := func(posture string) {
				t.Helper()
				if err := os.WriteFile(manifest, []byte(fmt.Sprintf(`{"posture":%q}`, posture)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			configRaw := func(mode string) []byte {
				return []byte(fmt.Sprintf("config_version: 9\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: %s\nguardrail:\n  enabled: true\n  connector: claudecode\n  hook_self_heal: true\n  hook_fail_mode: open\n  rule_pack: default\nobservability: {}\n", fixture.dataDir, mode))
			}
			writePosture(tc.before)
			initialRaw := configRaw("hot")
			if err := os.WriteFile(fixture.configPath, initialRaw, 0o600); err != nil {
				t.Fatal(err)
			}
			initial, err := config.LoadRuntimeV8File(fixture.configPath)
			if err != nil {
				t.Fatal(err)
			}
			notePackPosture(packDir, guardrail.ReadPackPosture(packDir))
			buildThresholdTable(initial, nil)
			publishPackPostures()
			published := fixture.sidecar.publishConfig(initial)
			fixture.sidecar.generation.Store(&Generation{Config: published})
			if got := hookPolicyTierForConnector(published, "claudecode"); got != tc.before {
				t.Fatalf("initial tier = %q, want %q", got, tc.before)
			}
			if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, initialRaw); err != nil || !bound {
				t.Fatalf("bootstrap bound=%t error=%v", bound, err)
			}
			mgr := newConfigManagerWithSnapshot(fixture.configPath, initial, nil, nil,
				fixture.sidecar.observabilityV8ActivePlanDigest(),
				func(ctx context.Context, oldCfg, newCfg *config.Config, diff ConfigDiff, source configReloadSource) error {
					if !onlyConfigReloadModeChanged(oldCfg, newCfg) || len(diff.Changed) != 1 || diff.Changed[0] != "gateway" {
						t.Fatalf("manager needs mode-only reload: changed=%v restart=%v mode-only=%t", diff.Changed, diff.RestartRequired, onlyConfigReloadModeChanged(oldCfg, newCfg))
					}
					return fixture.sidecar.applyConfigReloadSnapshot(ctx, oldCfg, newCfg, diff, source)
				})

			writePosture(tc.after)
			if err := os.WriteFile(fixture.configPath, configRaw("restart"), 0o600); err != nil {
				t.Fatal(err)
			}
			candidate, err := config.LoadRuntimeV8File(fixture.configPath)
			if err != nil {
				t.Fatal(err)
			}
			diff := diffConfigs(initial, candidate)
			if !onlyConfigReloadModeChanged(initial, candidate) || len(diff.Changed) != 1 || diff.Changed[0] != "gateway" {
				t.Fatalf("fixture needs mode-only reload: changed=%v restart=%v mode-only=%t", diff.Changed, diff.RestartRequired, onlyConfigReloadModeChanged(initial, candidate))
			}
			if err := mgr.Reload(t.Context(), "test"); err != nil {
				t.Fatal(err)
			}
			current := fixture.sidecar.currentConfig()
			if current == published && tc.before != tc.after {
				t.Fatal("mode-only reload reused the previous published config")
			}
			if got := hookPolicyTierForConnector(published, "claudecode"); got != tc.before {
				t.Fatalf("previous tier = %q, want %q", got, tc.before)
			}
			if got := hookPolicyTierForConnector(current, "claudecode"); got != tc.after {
				t.Fatalf("current tier = %q, want %q", got, tc.after)
			}
			if got := hookRuntimePolicyChanged(published, current, "claudecode"); got != (tc.before != tc.after) {
				t.Fatalf("hook policy changed = %t, want %t", got, tc.before != tc.after)
			}
			if current.Gateway.ConfigReload.Mode != "hot" || mgr.Current().Gateway.ConfigReload.Mode != "restart" {
				t.Fatalf("sidecar/manager mode = %q/%q, want hot/restart", current.Gateway.ConfigReload.Mode, mgr.Current().Gateway.ConfigReload.Mode)
			}
		})
	}
}
