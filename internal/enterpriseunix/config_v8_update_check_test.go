// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const v8UpdateCheckConfig = `config_version: 8
update_check: false
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
guardrail:
  enabled: true
  mode: observe
  connectors:
    codex: {}
`

// rel-1-0-2 GAP-0145: a managed config_version 8 file with the top-level
// update_check the 1.0.x CLI wrote was refused "update_check is an unknown
// setting" before the v9 migration that moves it to update.check ran. It is
// migrated now, as `config migrate` and the per-user upgrade do.
func TestEnsureMigratesAV8ConfigWithUpdateCheck(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireNoHostInstall(t, h.env.Layout)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(v8UpdateCheckConfig))}))
			installed := h.read(h.env.Layout.ConfigPath)
			if config.NeedsMigrationV9([]byte(installed)) || strings.Contains(installed, "update_check") {
				t.Fatalf("the installed config is not the v9 migration:\n%s", installed)
			}
			cfg, err := h.env.loadConfigCandidate([]byte(installed))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Update.CheckEnabled() {
				t.Fatalf("update.check = %v, want false (moved from update_check)", cfg.Update.Check)
			}
			requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: writeTempConfig(t, []byte(v8UpdateCheckConfig))}))
		})
	}
}

// The view only blanks update_check: another unknown key is still refused
// with its own line, and a value the migration cannot use is still refused.
func TestV8UpdateCheckViewKeepsOtherRefusals(t *testing.T) {
	h := newTestHost(t, "linux")
	unknown := strings.Replace(v8UpdateCheckConfig, "deployment_mode:", "not_a_setting: 1\ndeployment_mode:", 1)
	_, err := h.env.validateConfigSource([]byte(unknown), "/admin/config.yaml")
	if err == nil || !strings.Contains(err.Error(), "line 3") || !strings.Contains(err.Error(), "not_a_setting") {
		t.Fatalf("unknown key: %v, want a refusal naming not_a_setting on line 3", err)
	}
	if view := v8ChecksView([]byte(v8UpdateCheckConfig)); strings.Count(string(view), "\n") != strings.Count(v8UpdateCheckConfig, "\n") || strings.Contains(string(view), "update_check") {
		t.Fatalf("view changed the line count or kept update_check:\n%s", view)
	}
	v9 := strings.Replace(v8UpdateCheckConfig, "config_version: 8", "config_version: 9", 1)
	if got := string(v8ChecksView([]byte(v9))); got != v9 {
		t.Fatal("a config_version 9 file was changed by the v8 view")
	}
	block := strings.Replace(v8UpdateCheckConfig, "update_check: false", "update_check:\n  - false", 1)
	if got := string(v8ChecksView([]byte(block))); got != block {
		t.Fatal("a block value was blanked; the v8 checks must refuse it as before")
	}
}
