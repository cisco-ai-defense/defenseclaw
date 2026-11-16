//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestRepairManagedCodexUserFeature(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(home, ".codex")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(configDir, "config.toml")
	input := []byte("model = 'gpt-5'\n[features]\nhooks = false\nmulti_agent = true\n")
	if err := os.WriteFile(config, input, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := enterprisehooks.InstallOptions{ConnectorName: "codex", UserHome: home}
	for i := 0; i < 2; i++ {
		if i == 1 {
			opts.ConnectorName = "Codex"
		}
		if err := repairManagedCodexUserFeature(opts); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "hooks = false") || !strings.Contains(string(got), "model = 'gpt-5'") || !strings.Contains(string(got), "multi_agent = true") {
		t.Fatalf("repair changed other user settings or left conflicting feature: %q", got)
	}
	if err := os.WriteFile(config, []byte("[features]\nhooks = [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := repairManagedCodexUserFeature(opts); err == nil || !strings.Contains(err.Error(), "parse Codex user config") {
		t.Fatalf("malformed config did not name its cause: %v", err)
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(outside, input, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, config); err != nil {
		t.Fatal(err)
	}
	if err := repairManagedCodexUserFeature(opts); err == nil || !strings.Contains(err.Error(), "outside the enrolled home") {
		t.Fatalf("outside-home config mutation was not refused with a cause: %v", err)
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != string(input) {
		t.Fatalf("outside-home config was changed: %q, %v", got, err)
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "missing.toml"), config); err != nil {
		t.Fatal(err)
	}
	if err := repairManagedCodexUserFeature(opts); err == nil || !strings.Contains(err.Error(), "resolve Codex user config") {
		t.Fatalf("dangling user config link did not name its cause: %v", err)
	}
}

func TestRepairManagedCodexUserFeatureSymlinkedHome(t *testing.T) {
	realHome := t.TempDir()
	alias := filepath.Join(t.TempDir(), "user-home")
	if err := os.Symlink(realHome, alias); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(realHome, ".codex")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configDir, "config.toml")
	if err := os.WriteFile(path, []byte("[features]\nhooks = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := repairManagedCodexUserFeature(enterprisehooks.InstallOptions{
		ConnectorName: "codex", UserHome: alias,
	}); err != nil {
		t.Fatalf("repair through a symlinked enrolled home: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "hooks") {
		t.Fatalf("managed hooks preference was not removed: %q", got)
	}
}
