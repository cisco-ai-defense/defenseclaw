// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1802 (the lifecycle half of GAP-1694): the lifecycle's copy of the
// policy_dir check skips a writable rule pack folder no setting names, and
// still refuses a writable file inside the pack the config uses.
func TestLifecyclePolicyDirCheckSkipsOnlyUnreferencedRulePacks(t *testing.T) {
	h := newTestHost(t, "linux")
	policyDir := "/etc/defenseclaw/policies"
	for _, dir := range []string{"guardrail/stray", "guardrail/strict/rules"} {
		if err := os.MkdirAll(h.env.P(filepath.Join(policyDir, dir)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rule := h.env.P(filepath.Join(policyDir, "guardrail/strict/rules/a.yaml"))
	if err := os.WriteFile(rule, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	stray := h.env.P(filepath.Join(policyDir, "guardrail/stray"))
	if err := os.Chmod(stray, 0o777); err != nil {
		t.Fatal(err)
	}
	h.env.Trust = func(path string, _ TrustKind) error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s: group/other writable permissions %#o are not trusted", path, info.Mode().Perm())
		}
		return nil
	}
	cfg := &config.Config{PolicyDir: policyDir}
	cfg.Guardrail.RulePackDir = filepath.Join(policyDir, "guardrail", "strict")
	if err := h.env.checkManagedPolicyDir(cfg); err != nil {
		t.Fatalf("an unreferenced writable rule pack folder was refused: %v", err)
	}
	if err := os.Chmod(rule, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := h.env.checkManagedPolicyDir(cfg); err == nil {
		t.Fatal("a writable rule file in the pack the config uses was accepted")
	}
}
