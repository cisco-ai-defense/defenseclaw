// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// GAP-0686: Codex runs the .codex/config.toml of a project only when the user
// config trusts the project; the effective lookup follows that.
func TestLookupEffectiveCodexMCPToolServerFollowsProjectTrust(t *testing.T) {
	home := t.TempDir()
	codexHome := filepath.Join(home, ".codex")
	project := filepath.Join(t.TempDir(), "repo")
	write := func(path, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CODEX_HOME", codexHome)
	user := "[mcp_servers.notes]\nurl = \"https://user.example.invalid/mcp\"\n"
	write(filepath.Join(project, ".codex", "config.toml"), "[mcp_servers.notes]\nurl = \"https://project.example.invalid/mcp\"\n[mcp_servers.extra]\nurl = \"https://extra.example.invalid/mcp\"\n")
	lookup := func(name string) (string, bool) {
		entry, ok := LookupEffectiveCodexMCPToolServer(project, name)
		return entry.URL, ok
	}

	write(filepath.Join(codexHome, "config.toml"), user)
	if url, ok := lookup("notes"); !ok || url != "https://user.example.invalid/mcp" {
		t.Fatalf("untrusted project: notes = %q ok=%v, want the user definition", url, ok)
	}
	if url, ok := lookup("extra"); ok {
		t.Fatalf("untrusted project defined a server that ran: %q", url)
	}
	other := user + "\n[projects." + strconv.Quote(filepath.Join(t.TempDir(), "other")) + "]\ntrust_level = \"trusted\"\n"
	write(filepath.Join(codexHome, "config.toml"), other)
	if url, _ := lookup("notes"); url != "https://user.example.invalid/mcp" {
		t.Fatalf("a trusted unrelated project trusted this one: %q", url)
	}
	untrusted := user + "\n[projects." + strconv.Quote(project) + "]\ntrust_level = \"untrusted\"\n"
	write(filepath.Join(codexHome, "config.toml"), untrusted)
	if url, _ := lookup("notes"); url != "https://user.example.invalid/mcp" {
		t.Fatalf("an untrusted project overrode the user definition: %q", url)
	}

	// Protected: a trusted project (the layer itself, or a folder above it) and
	// a user config that cannot be read keep the project definition in effect.
	for name, text := range map[string]string{
		"project": user + "\n[projects." + strconv.Quote(project) + "]\ntrust_level = \"trusted\"\n",
		"parent":  user + "\n[projects." + strconv.Quote(filepath.Dir(project)) + "]\ntrust_level = \"trusted\"\n",
	} {
		write(filepath.Join(codexHome, "config.toml"), text)
		if url, _ := lookup("notes"); url != "https://project.example.invalid/mcp" {
			t.Fatalf("trusted %s: notes = %q, want the project definition", name, url)
		}
		if _, ok := lookup("extra"); !ok {
			t.Fatalf("trusted %s: the project server was dropped", name)
		}
	}
	write(filepath.Join(codexHome, "config.toml"), "[mcp_servers.notes\n")
	if _, ok := lookup("extra"); !ok {
		t.Fatal("a user config that cannot be read dropped a project server; trust unknown must keep it in effect")
	}
}
