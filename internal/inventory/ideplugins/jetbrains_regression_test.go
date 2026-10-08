// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJetBrainsUnknownWhenDisabledListCannotBeRead(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, ".config", "JetBrains", "PyCharm2024.1")
	plugins := filepath.Join(home, ".local", "share", "JetBrains", "PyCharm2024.1")
	writeJar(t, filepath.Join(plugins, "example.jar"), `<idea-plugin><id>com.example.plugin</id></idea-plugin>`)
	if err := os.MkdirAll(filepath.Join(config, "disabled_plugins.txt"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := byID(Scan(home, "linux", Limits{}), FamilyJetBrains, "pycharm", "")["com.example.plugin|user"]
	if got.Enabled != EnabledUnknown || got.EnabledSource != SourceUnknown {
		t.Fatalf("unreadable disabled list: %+v", got)
	}
	if err := os.RemoveAll(filepath.Join(config, "disabled_plugins.txt")); err != nil {
		t.Fatal(err)
	}
	got = byID(Scan(home, "linux", Limits{}), FamilyJetBrains, "pycharm", "")["com.example.plugin|user"]
	if got.Enabled != EnabledOn || got.EnabledSource != SourceDefault {
		t.Fatalf("absent disabled list: %+v", got)
	}
}
