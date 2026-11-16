// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-0122: the root guardian watches the target user's Hermes folder and
// config, not the ones under its own home, so an in-place rewrite of the
// user's config starts a pass.
func TestWatchPathsNameTheTargetUsersHermesConfig(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	previousOverride := connector.HermesConfigPathOverride
	connector.HermesConfigPathOverride = ""
	t.Cleanup(func() { connector.HermesConfigPathOverride = previousOverride })
	guardianHome := t.TempDir()
	t.Setenv("HOME", guardianHome)
	t.Setenv("HERMES_HOME", "")
	home := newTestHome(t)
	hermesDir := filepath.Join(home, ".hermes")
	if err := os.MkdirAll(hermesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(hermesDir, "config.yaml")
	if err := os.WriteFile(config, []byte("hooks: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := InstallOptions{
		ConnectorName: "hermes",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      strings.Repeat("a", 64),
		GuardrailMode: "action",
		HookFailMode:  "closed",
		Registry:      connector.NewDefaultRegistry(),
	}
	dirs, err := WatchDirs(opts)
	if err != nil {
		t.Fatalf("WatchDirs: %v", err)
	}
	if !sliceContains(dirs, hermesDir) {
		t.Fatalf("WatchDirs = %v, missing the user's %s", dirs, hermesDir)
	}
	own, err := WatchOwnedFiles(opts)
	if err != nil {
		t.Fatalf("WatchOwnedFiles: %v", err)
	}
	if !sliceContains(own.SharedWriter, config) {
		t.Fatalf("WatchOwnedFiles.SharedWriter = %v, missing the user's %s", own.SharedWriter, config)
	}
	for _, path := range append(append(dirs, own.SharedWriter...), own.ExclusiveWriter...) {
		if strings.HasPrefix(path, guardianHome) {
			t.Fatalf("watch path %s is under the guardian's own home", path)
		}
	}
}
