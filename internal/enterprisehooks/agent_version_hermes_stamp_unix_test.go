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

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// GAP-1274: a Hermes CLI upgraded outside its installer leaves the install
// stamp naming the older release. The CLI's own --version wins; the stamp
// names the release only when the CLI does not answer (a current Hermes
// refuses --version outside its environment) or nothing may be run.
func TestDiscoverUnixAgentVersionPrefersTheHermesCLIOverAStaleStamp(t *testing.T) {
	home := t.TempDir()
	stampDir := filepath.Join(home, ".hermes", "hermes-agent")
	bin := filepath.Join(home, ".local", "bin")
	for _, dir := range []string{stampDir, bin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stampDir, "install-stamp.json"), []byte(`{"baseVersion":"0.21.5","displayVersion":"0.21.5"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(bin, "hermes")
	for _, tc := range []struct {
		name, body string
		allowExec  bool
		want       string
	}{
		{"the CLI answers", "#!/bin/sh\necho \"Hermes Agent v0.22.0\"\n", true, "0.22.0"},
		{"the CLI refuses --version", "#!/bin/sh\necho \"no committed environment\" >&2\nexit 1\n", true, "0.21.5"},
		{"nothing may be run", "#!/bin/sh\necho \"Hermes Agent v0.22.0\"\n", false, "0.21.5"},
	} {
		if err := os.WriteFile(cli, []byte(tc.body), 0o755); err != nil {
			t.Fatal(err)
		}
		if got, reason := DiscoverUnixAgentVersion(context.Background(), home, "hermes", tc.allowExec); got != tc.want {
			t.Fatalf("%s: version = %q (%s), want %q", tc.name, got, reason, tc.want)
		}
	}
}
