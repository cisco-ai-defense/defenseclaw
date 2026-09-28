// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermespath

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestConfigPathForUserHomeUsesTheTargetProfile(t *testing.T) {
	if got := ConfigPathForUserHome("   "); got != "" {
		t.Fatalf("empty home = %q, want empty", got)
	}
	home := filepath.Join(t.TempDir(), "alice")
	want := filepath.Join(home, ".hermes", "config.yaml")
	if runtime.GOOS == "windows" {
		want = filepath.Join(home, "AppData", "Local", "hermes", "config.yaml")
	}
	if got := ConfigPathForUserHome(home); got != want {
		t.Fatalf("ConfigPathForUserHome = %q, want %q", got, want)
	}
}
