// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// GAP-1694: the gateway's policy build and the config validation share one
// policy_dir check (ValidateManagedPolicyDir). An unreferenced writable rule
// pack folder passes; a writable file inside the pack a setting names, the
// Rego and data files are still refused.
func TestValidateManagedPolicyDirSkipsOnlyUnreferencedRulePacks(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"rego", "guardrail/stray", "guardrail/strict/rules"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"rego/guardrail.rego", "guardrail/stray/x.yaml", "guardrail/strict/rules/a.yaml"} {
		if err := os.WriteFile(filepath.Join(root, file), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	untrusted := map[string]bool{}
	fake := func(path, _, _ string) error {
		rel, _ := filepath.Rel(root, path)
		for bad := range untrusted {
			if rel == filepath.FromSlash(bad) || len(rel) > len(bad) && rel[:len(bad)+1] == filepath.FromSlash(bad)+string(filepath.Separator) {
				return fmt.Errorf("%s: group/other writable permissions 0777 are not trusted", path)
			}
		}
		return nil
	}
	previous := managedPolicyTreeChecks
	managedPolicyTreeChecks = policyTreeChecks{dir: fake, file: fake, tree: func(path, label, account string) error {
		// The tree check covers everything below path.
		return filepath.WalkDir(path, func(cur string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return fake(cur, label, account)
		})
	}}
	t.Cleanup(func() { managedPolicyTreeChecks = previous })
	cfg := &Config{PolicyDir: root}
	cfg.Guardrail.RulePackDir = filepath.Join(root, "guardrail", "strict")

	untrusted["guardrail/stray"] = true
	if err := ValidateManagedPolicyDir(cfg, root, ""); err != nil {
		t.Fatalf("an unreferenced writable rule pack folder was refused: %v", err)
	}
	for _, bad := range []string{"guardrail/strict/rules/a.yaml", "rego/guardrail.rego", "guardrail"} {
		untrusted = map[string]bool{bad: true}
		if err := ValidateManagedPolicyDir(cfg, root, ""); err == nil {
			t.Fatalf("a writable %s was accepted", bad)
		}
	}
}

// GAP-1802: on the case-insensitive macOS and Windows volumes a referenced
// pack spelled with another case is the same folder and keeps its check.
func TestPathHoldsAnyIgnoresCaseOnCaseInsensitiveVolumes(t *testing.T) {
	dir := filepath.Join("/etc", "defenseclaw", "policies", "guardrail", "strict")
	referenced := []string{filepath.Join("/etc", "defenseclaw", "policies", "guardrail", "Strict")}
	for goos, want := range map[string]bool{"darwin": true, "windows": true, "linux": false} {
		if got := pathHoldsAny(goos, dir, referenced); got != want {
			t.Fatalf("%s: pathHoldsAny = %v, want %v", goos, got, want)
		}
	}
	if !pathHoldsAny("linux", filepath.Dir(dir), referenced) {
		t.Fatal("the guardrail folder holds the referenced pack")
	}
}
