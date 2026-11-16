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

import "testing"

// An administrator who sets asset_policy.mcp.runtime_detection enabled and
// terminal_commands to false turns MCP runtime detection off; the setting is
// not read back as the default (GAP-0947). Absent from the file, or on a
// struct that never went through config load, it stays on.
func TestMCPRuntimeDetectionExplicitOffIsKept(t *testing.T) {
	load := func(t *testing.T, body string) AssetRuntimeDetection {
		t.Helper()
		cfg, err := LoadRuntimeV8FromBytes("config.yaml", []byte("config_version: 9\n"+body))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := cfg.AssetRuntimeDetectionFor("mcp")
		if !ok {
			t.Fatal("no mcp runtime detection")
		}
		return got
	}
	if got := load(t, "asset_policy:\n  mcp:\n    runtime_detection: {enabled: false, terminal_commands: false}\n"); got.Enabled || got.TerminalCommands {
		t.Fatalf("explicit off = %+v, want detection off", got)
	}
	if got := load(t, "asset_policy:\n  mcp:\n    runtime_detection: {enabled: false}\n"); got.Enabled {
		t.Fatalf("enabled false = %+v, want detection off", got)
	}
	if got := load(t, "asset_policy:\n  enabled: true\n"); !got.Enabled || !got.TerminalCommands {
		t.Fatalf("unset = %+v, want the default on", got)
	}
	if got, _ := (&Config{}).AssetRuntimeDetectionFor("mcp"); !got.Enabled || !got.TerminalCommands {
		t.Fatalf("zero-value config = %+v, want the default on", got)
	}
}
