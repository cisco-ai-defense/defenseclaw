// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// GAP-0686 review 5: the entry nearest a project decides its trust. A project
// marked untrusted below a trusted folder is not trusted, a trusted project
// below an untrusted folder is, and the ordinary trusted-parent project keeps
// its definition in effect.
func TestLookupEffectiveCodexMCPToolServerNearestTrustEntryDecides(t *testing.T) {
	root := t.TempDir()
	codexHome := filepath.Join(t.TempDir(), ".codex")
	t.Setenv("CODEX_HOME", codexHome)
	write := func(path, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	child := filepath.Join(root, "child")
	deeper := filepath.Join(child, "pkg")
	write(filepath.Join(child, ".git", "HEAD"), "ref: refs/heads/main\n")
	write(filepath.Join(child, ".codex", "config.toml"), "[mcp_servers.notes]\nurl = \"https://project.example.invalid/mcp\"\n")
	user := "[mcp_servers.notes]\nurl = \"https://user.example.invalid/mcp\"\n"
	entry := func(path, level string) string {
		return "[projects." + strconv.Quote(path) + "]\ntrust_level = \"" + level + "\"\n"
	}
	for _, tc := range []struct {
		name, cwd, projects string
		project             bool
	}{
		{"untrusted child below trusted parent", child, entry(root, "trusted") + entry(child, "untrusted"), false},
		{"untrusted child, working folder deeper", deeper, entry(root, "trusted") + entry(child, "untrusted"), false},
		{"untrusted child, odd level below trusted parent", child, entry(root, "trusted") + entry(child, "other"), false},
		{"trusted child below untrusted parent", child, entry(root, "untrusted") + entry(child, "trusted"), true},
		{"trusted parent only", child, entry(root, "trusted"), true},
		{"trusted child only", child, entry(child, "trusted"), true},
		{"trusted working folder inside an untrusted layer", deeper, entry(child, "untrusted") + entry(deeper, "trusted"), true},
		{"same path spelled twice, one trusted", child, entry(child, "untrusted") + entry(strings.ToUpper(child), "trusted"), true},
	} {
		write(filepath.Join(codexHome, "config.toml"), user+"\n"+tc.projects)
		got, ok := LookupEffectiveCodexMCPToolServer(tc.cwd, "notes")
		want := "https://user.example.invalid/mcp"
		if tc.project {
			want = "https://project.example.invalid/mcp"
		}
		if !ok || got.URL != want {
			t.Errorf("%s: notes = %q ok=%v, want %q", tc.name, got.URL, ok, want)
		}
	}
}
