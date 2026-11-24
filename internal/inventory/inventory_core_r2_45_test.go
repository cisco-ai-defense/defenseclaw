// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClaudeProjectSkillsSkipMacOSProtectedProject(t *testing.T) {
	oldOS, oldFDA := discoveryGOOS, macOSFullDiskAccess
	t.Cleanup(func() { discoveryGOOS, macOSFullDiskAccess = oldOS, oldFDA })
	discoveryGOOS = "darwin"
	macOSFullDiskAccess = func() bool { return false }
	home := t.TempDir()
	project := filepath.Join(home, "Documents", "project")
	link := filepath.Join(home, "work", "linked-project")
	if err := os.MkdirAll(filepath.Join(project, ".claude", "skills", "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(project, link); err != nil {
		t.Fatal(err)
	}
	state := `{"projects":{"` + filepath.ToSlash(project) + `":{},"` + filepath.ToSlash(link) + `":{}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home, HomeDirs: []string{home}},
		catalog: []AISignature{{ID: "claudecode"}}}
	signals, err := svc.detectClaudeProjectSkills()
	if err == nil || len(signals) != 0 || !svc.tccSkipped {
		t.Fatalf("protected project: signals=%+v warning=%v skipped=%v", signals, err, svc.tccSkipped)
	}
	svc.opts.ScanRoots = []string{project}
	signals, err = svc.detectClaudeProjectSkills()
	if err == nil || len(signals) != 1 {
		t.Fatalf("explicit project: signals=%+v warning=%v", signals, err)
	}
}

func TestSecureClientDoesNotPreSkipMacOSPrivacyFolder(t *testing.T) {
	oldOS, oldFDA := discoveryGOOS, macOSFullDiskAccess
	t.Cleanup(func() { discoveryGOOS, macOSFullDiskAccess = oldOS, oldFDA })
	discoveryGOOS = "darwin"
	macOSFullDiskAccess = func() bool { return false }
	home := t.TempDir()
	svc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home, SecureClient: true}}
	if svc.macOSTCCSkipped(filepath.Join(home, "Documents")) {
		t.Fatal("Secure Client pre-skipped a readable folder")
	}
}
