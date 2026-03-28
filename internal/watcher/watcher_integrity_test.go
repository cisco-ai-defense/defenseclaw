// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

func TestPostInstallIntegrity_AllowListBaseline(t *testing.T) {
	t.Parallel()
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Integrity = config.IntegrityConfig{
		Enabled:    true,
		Skill:      true,
		TrustLevel: "allow_list",
		OnDrift:    "alert",
	}
	if err := store.SetActionField("skill", "s1", "install", "allow", "pre-approved"); err != nil {
		t.Fatal(err)
	}
	skillPath := filepath.Join(skillDir, "s1")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, nil)

	evt := InstallEvent{Type: InstallSkill, Name: "s1", Path: skillPath}
	res := w.runAdmission(context.Background(), evt)
	if res.Verdict != VerdictAllowed {
		t.Fatalf("verdict %s", res.Verdict)
	}
	w.postInstallIntegrity(context.Background(), evt, res)

	b, err := store.GetIntegrityBaseline("skill", "s1")
	if err != nil || b == nil || b.Fingerprint == "" {
		t.Fatalf("baseline missing: %v %+v", err, b)
	}

	if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}

	absRoot, err := filepath.Abs(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	w.runIntegrityDriftCheck(context.Background(), absRoot)

	alerts, err := store.ListAlerts(50)
	if err != nil {
		t.Fatal(err)
	}
	var drift bool
	for _, e := range alerts {
		if e.Action == "integrity-drift" {
			drift = true
			break
		}
	}
	if !drift {
		t.Fatal("expected integrity-drift in alerts after file change")
	}
}
