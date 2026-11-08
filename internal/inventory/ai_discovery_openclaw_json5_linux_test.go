// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import "testing"

func TestBrokeredNamesReadAJSON5OpenClawConfig(t *testing.T) {
	data := []byte("// mine\n{gateway:{port:0x4965},mcp:{servers:{demo:{command:'echo'}}}}")
	names, truncated, err := parseMCPConfigBytesForNames(mcpShapeOpenClaw, "openclaw.json", data, 100)
	if err != nil || truncated || len(names) != 1 || names[0] != "demo" {
		t.Fatalf("names, truncated, err = %v, %t, %v, want [demo]", names, truncated, err)
	}
}
