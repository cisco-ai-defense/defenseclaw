//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A per-user install links skill-scanner from the venv; the gateway runs the
// DefenseClaw entry point beside it (GAP-2609).
func TestResolveDefaultSkillScannerPrefersJudgeCompatEntry(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	venvBin := t.TempDir()
	linkDir := t.TempDir()
	installed := filepath.Join(venvBin, "skill-scanner")
	entry := filepath.Join(venvBin, judgeCompatSkillScanner)
	for _, path := range []string{installed, entry} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(linkDir, "skill-scanner")
	if err := os.Symlink(installed, link); err != nil {
		t.Fatal(err)
	}
	old := lookSkillScanner
	t.Cleanup(func() { lookSkillScanner = old })
	lookSkillScanner = func(string) (string, error) { return link, nil }

	if got, err := resolveDefaultSkillScanner("skill-scanner", false); err != nil || got != entry {
		t.Fatalf("resolveDefaultSkillScanner = %q, %v; want %q", got, err, entry)
	}
	for name, binary := range map[string]string{"configured binary": "/opt/other/skill-scanner", "runtime launcher": "/opt/defenseclaw/bin/defenseclaw-scanners"} {
		if got, _ := resolveDefaultSkillScanner(binary, false); got != binary {
			t.Errorf("%s: got %q, want it unchanged", name, got)
		}
	}
	if got, _ := resolveDefaultSkillScanner("skill-scanner", true); got != "skill-scanner" {
		t.Errorf("secure client: got %q", got)
	}
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	if got, _ := resolveDefaultSkillScanner("skill-scanner", false); got != "skill-scanner" {
		t.Errorf("managed: got %q", got)
	}
	t.Setenv(managed.DeploymentModeEnv, "")

	if err := os.Chmod(entry, 0o775); err != nil {
		t.Fatal(err)
	}
	if got, _ := resolveDefaultSkillScanner("skill-scanner", false); got != "skill-scanner" {
		t.Errorf("group-writable entry point: got %q, want the bare command", got)
	}
	if err := os.Remove(entry); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(installed, entry); err != nil {
		t.Fatal(err)
	}
	if got, _ := resolveDefaultSkillScanner("skill-scanner", false); got != "skill-scanner" {
		t.Errorf("linked entry point: got %q, want the bare command", got)
	}
	if err := os.Remove(entry); err != nil {
		t.Fatal(err)
	}
	if got, _ := resolveDefaultSkillScanner("skill-scanner", false); got != "skill-scanner" {
		t.Errorf("older wheel without the entry point: got %q", got)
	}
	lookSkillScanner = func(string) (string, error) { return "", errors.New("not found") }
	if got, _ := resolveDefaultSkillScanner("skill-scanner", false); got != "skill-scanner" {
		t.Errorf("no skill-scanner on PATH: got %q", got)
	}
}
