//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/productlayout"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// TestInstallWindowsShippedRulePacksConverges covers #1445: the lifecycle
// helper writes this release's packs once, a repeated run changes nothing,
// a changed or added file is replaced by a checked copy, and uninstall's
// removal takes the root.
func TestInstallWindowsShippedRulePacksConverges(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("setting the Administrators owner needs an elevated token")
	}
	root := filepath.Join(t.TempDir(), productlayout.WindowsRulePacksFolder)
	savedRoot, savedTrust := windowsShippedRulePacksRootDir, windowsShippedRulePacksTreeTrust
	windowsShippedRulePacksRootDir = func() (string, error) { return root, nil }
	// The temporary folder's parents are the test account's, which the
	// production trust check refuses; the access list itself is checked below.
	windowsShippedRulePacksTreeTrust = func(string, string, string) error { return nil }
	t.Cleanup(func() { windowsShippedRulePacksRootDir, windowsShippedRulePacksTreeTrust = savedRoot, savedTrust })

	folder, changed, _, err := installWindowsShippedRulePacks()
	if err != nil || !changed {
		t.Fatalf("first run = %q changed %v, %v", folder, changed, err)
	}
	files, err := policyassets.ShippedRulePackFiles()
	if err != nil {
		t.Fatal(err)
	}
	if problem := windowsShippedRulePacksProblem(folder, files, ""); problem != "" {
		t.Fatalf("written folder: %s", problem)
	}
	if owned, err := windowsPathOwnedByAdministrators(folder); err != nil || !owned {
		t.Fatalf("folder owner trusted = %v, %v", owned, err)
	}
	if _, changed, _, err := installWindowsShippedRulePacks(); err != nil || changed {
		t.Fatalf("repeat run changed %v, %v; want no change", changed, err)
	}

	suppressions := filepath.Join(folder, "strict", "suppressions.yaml")
	if err := os.WriteFile(suppressions, []byte("suppressions: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "strict", "rules", "extra.yaml"), []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, _, err := installWindowsShippedRulePacks(); err != nil || !changed {
		t.Fatalf("run after an edit changed %v, %v; want a rewrite", changed, err)
	}
	if problem := windowsShippedRulePacksProblem(folder, files, ""); problem != "" {
		t.Fatalf("rewritten folder: %s", problem)
	}
	for _, file := range files {
		if file.Path == "strict/suppressions.yaml" {
			got, err := os.ReadFile(suppressions)
			if err != nil || !bytes.Equal(got, file.Data) {
				t.Fatalf("suppressions.yaml was not restored: %v", err)
			}
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("root holds %d entries (%v), want only the release folder", len(entries), err)
	}

	if err := removeWindowsShippedRulePacksRoot(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("root stays after removal: %v", err)
	}
}
