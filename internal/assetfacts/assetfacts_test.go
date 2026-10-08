// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"strings"
	"testing"
)

func TestEncodePreservesPinnedMCPWithLargeArguments(t *testing.T) {
	args := make([]string, 7)
	for i := range args {
		args[i] = strings.Repeat("x", 900)
	}
	want := MCPServer{
		Name: "notes", URL: "https://example.test/mcp",
		Command: "server", Args: args, Transport: "http",
	}
	header := Encode(Facts{MCP: &want})
	got, ok := Decode(header)
	if !ok || got.MCP == nil {
		t.Fatalf("MCP facts missing from encoded header")
	}
	if got.MCP.URL != want.URL || got.MCP.Command != want.Command ||
		got.MCP.Transport != want.Transport || len(got.MCP.Args) != len(want.Args) {
		t.Fatalf("pinned MCP facts changed: %#v", got.MCP)
	}
	for i := range args {
		if got.MCP.Args[i] != args[i] {
			t.Fatalf("MCP argument %d changed", i)
		}
	}
}
