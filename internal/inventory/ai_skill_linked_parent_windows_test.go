// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2001 on Windows: a .claude folder that is a junction into a dotfiles
// folder keeps every skill fact; a junctioned skill folder stays refused.
func TestGAP2001SkillFactsThroughJunctionedAgentFolder(t *testing.T) {
	home := t.TempDir()
	const body = "---\nname: s\ndescription: linked skill\n---\nbody\n"
	real := filepath.Join(home, "dotfiles", "claude", "skills", "s")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "SKILL.md"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	mklinkJunction(t, filepath.Join(home, ".claude"), filepath.Join(home, "dotfiles", "claude"))
	s := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home}}
	facts := s.skillFacts(filepath.Join(home, ".claude", "skills", "s"), false)
	if facts == nil || facts.ContentStatus != SkillContentOK || facts.ContentHash == "" || facts.Description != "linked skill" {
		t.Fatalf("facts through a junction = %+v", facts)
	}
	if data, ok := s.SkillManifest(facts.ManifestHash); !ok || string(data) != body {
		t.Fatalf("SKILL.md readback = %q, %t", data, ok)
	}
	mklinkJunction(t, filepath.Join(home, "dotfiles", "claude", "skills", "j"), real)
	if hash, status, _ := hashSkillFolder(filepath.Join(home, ".claude", "skills", "j"), maxSkillBytes); hash != "" || status != SkillContentSymlink {
		t.Fatalf("junctioned skill folder = %q, %s", hash, status)
	}
}
