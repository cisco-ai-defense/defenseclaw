// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestFingerprintDir_Deterministic(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "nested")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "x.txt"), []byte("z"), 0o600); err != nil {
		t.Fatal(err)
	}

	a, n1, err := FingerprintDir(root)
	if err != nil {
		t.Fatal(err)
	}
	b, n2, err := FingerprintDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("fingerprints differ: %s vs %s", a, b)
	}
	if n1 != 2 || n2 != 2 {
		t.Fatalf("file count: got %d and %d", n1, n2)
	}

	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, err := FingerprintDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Fatal("expected fingerprint to change after edit")
	}
}

func TestFingerprintDir_SkipsGitDir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	fp1, _, err := FingerprintDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	fp2, _, err := FingerprintDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatal(".git changes should not affect fingerprint")
	}
}

func TestFingerprintMCPServer_Stable(t *testing.T) {
	t.Parallel()
	e1 := config.MCPServerEntry{
		Name:    "s",
		Command: "node",
		Args:    []string{"b", "a"},
		Env:     map[string]string{"Z": "1", "A": "2"},
		URL:     "http://x",
	}
	e2 := config.MCPServerEntry{
		Name:    "s",
		Command: "node",
		Args:    []string{"a", "b"},
		Env:     map[string]string{"A": "2", "Z": "1"},
		URL:     "http://x",
	}
	h1, err := FingerprintMCPServer(e1)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := FingerprintMCPServer(e2)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("expected stable hash, got %s vs %s", h1, h2)
	}
	e3 := config.MCPServerEntry{Name: "s", Command: "node", Args: []string{"a", "b"}}
	h3, err := FingerprintMCPServer(e3)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h3 {
		t.Fatal("expected different hash when env/url differ")
	}
}
