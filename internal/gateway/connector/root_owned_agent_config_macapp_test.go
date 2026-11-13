//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The macOS app's administrator helper returns root-owned agent config files
// from a fixed list (GatewayAdminAgentConfigRepair.relativePaths: no path may
// cross its XPC boundary). That list must stay the default candidate set of
// RootOwnedAgentConfigPaths, so a new or moved connector file reaches the
// helper's repair too.
func TestMacHelperAgentConfigListMatchesConnectors(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "macos", "DefenseClawMac", "GatewayAdminHelper", "main.swift"))
	if err != nil {
		t.Fatalf("read helper source: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "// BEGIN agentConfigPaths")
	end := strings.Index(text, "// END agentConfigPaths")
	if start < 0 || end < start {
		t.Fatal("agentConfigPaths markers not found in GatewayAdminHelper/main.swift")
	}
	var swift []string
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(text[start:end], -1) {
		swift = append(swift, m[1])
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, kv := range os.Environ() {
		key := kv[:strings.IndexByte(kv, '=')]
		if strings.HasSuffix(key, "_HOME") || strings.HasPrefix(key, "XDG_") || strings.HasPrefix(key, "CLAUDE_") ||
			strings.HasPrefix(key, "CODEX_") || strings.HasPrefix(key, "DEFENSECLAW_") || strings.HasPrefix(key, "OPENCODE_") {
			t.Setenv(key, "")
			os.Unsetenv(key)
		}
	}
	opts := SetupOpts{DataDir: filepath.Join(home, ".defenseclaw")}
	seen := map[string]bool{}
	var want []string
	registry := NewDefaultRegistry()
	for _, name := range registry.Names() {
		conn, ok := registry.Get(name)
		if !ok {
			continue
		}
		candidates := HookConfigPathsForConnector(conn, opts)
		if provider, ok := conn.(AgentPathProvider); ok {
			candidates = append(candidates, provider.AgentPaths(opts).PatchedFiles...)
		}
		for _, path := range candidates {
			path = filepath.Clean(path)
			if !filepath.IsAbs(path) || path == home || !managedPathWithin(path, home) {
				continue
			}
			rel, err := filepath.Rel(home, path)
			if err != nil || seen[rel] {
				continue
			}
			seen[rel] = true
			want = append(want, filepath.ToSlash(rel))
		}
	}
	sort.Strings(want)
	got := append([]string(nil), swift...)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("GatewayAdminAgentConfigRepair.relativePaths drifted from the connectors' agent config files.\nswift:\n  %s\nconnectors:\n  %s",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}
