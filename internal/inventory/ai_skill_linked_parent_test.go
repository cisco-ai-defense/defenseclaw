// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

const gap2001Manifest = "---\nname: s\ndescription: linked skill\nversion: 1.2.3\n---\nbody\n"

// gap2001Skill writes a skill at home/dotfiles/claude/skills/s and returns it.
func gap2001Skill(t *testing.T, home string) string {
	t.Helper()
	skill := filepath.Join(home, "dotfiles", "claude", "skills", "s")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte(gap2001Manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return skill
}

func gap2001Check(t *testing.T, home, path, location, wantHash string) {
	t.Helper()
	s := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home}}
	facts := s.skillFacts(path, false)
	if facts == nil || facts.ContentStatus != SkillContentOK || facts.ContentHash == "" ||
		facts.Description != "linked skill" || facts.Version != "1.2.3" || facts.Location != location {
		t.Fatalf("facts through a linked parent = %+v; want ok, hash, description, version, %s", facts, location)
	}
	if wantHash != "" && facts.ContentHash != wantHash {
		t.Fatalf("hash through the link = %s, want the real folder's %s", facts.ContentHash, wantHash)
	}
	if data, ok := s.SkillManifest(facts.ManifestHash); !ok || string(data) != gap2001Manifest {
		t.Fatalf("SKILL.md readback = %q, %t", data, ok)
	}
}

// GAP-2001: ~/.claude linked into a dotfiles repo (stow, chezmoi) keeps every
// skill fact, as on rel.
func TestGAP2001SkillFactsThroughLinkedAgentFolder(t *testing.T) {
	home := t.TempDir()
	real := gap2001Skill(t, home)
	if err := os.Symlink(filepath.Join(home, "dotfiles", "claude"), filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	direct := (&ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home}}).skillFacts(real, false)
	if direct == nil || direct.ContentStatus != SkillContentOK {
		t.Fatalf("real folder facts = %+v", direct)
	}
	gap2001Check(t, home, filepath.Join(home, ".claude", "skills", "s"), "~/.claude/skills/s", direct.ContentHash)
}

// GAP-2001: a linked home (/home -> /var/home) keeps every skill fact too.
func TestGAP2001SkillFactsThroughLinkedHome(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "var", "home", "u"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "var", "home"), filepath.Join(base, "home")); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home", "u")
	gap2001Skill(t, home)
	gap2001Check(t, home, filepath.Join(home, "dotfiles", "claude", "skills", "s"), "~/dotfiles/claude/skills/s", "")
}
