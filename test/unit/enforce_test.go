// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package unit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

func newTestStore(t *testing.T) *audit.Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		store.Close()
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestPolicyEngineBlockAndCheck(t *testing.T) {
	store := newTestStore(t)
	pe := enforce.NewPolicyEngine(store)

	blocked, err := pe.IsBlocked("skill", "test-skill")
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if blocked {
		t.Fatal("expected not blocked before adding")
	}

	if err := pe.Block("skill", "test-skill", "security risk"); err != nil {
		t.Fatalf("Block: %v", err)
	}

	blocked, err = pe.IsBlocked("skill", "test-skill")
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if !blocked {
		t.Fatal("expected blocked after adding")
	}
}

func TestPolicyEngineAllowAndCheck(t *testing.T) {
	store := newTestStore(t)
	pe := enforce.NewPolicyEngine(store)

	if err := pe.Allow("mcp", "https://safe.example.com", "verified"); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	allowed, err := pe.IsAllowed("mcp", "https://safe.example.com")
	if err != nil {
		t.Fatalf("IsAllowed: %v", err)
	}
	if !allowed {
		t.Fatal("expected allowed after adding")
	}
}

func TestPolicyEngineBlockRemovesAllow(t *testing.T) {
	store := newTestStore(t)
	pe := enforce.NewPolicyEngine(store)

	if err := pe.Allow("skill", "dual-skill", "initially allowed"); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	allowed, _ := pe.IsAllowed("skill", "dual-skill")
	if !allowed {
		t.Fatal("expected allowed")
	}

	if err := pe.Block("skill", "dual-skill", "now blocked"); err != nil {
		t.Fatalf("Block: %v", err)
	}

	allowed, _ = pe.IsAllowed("skill", "dual-skill")
	if allowed {
		t.Fatal("expected not allowed after blocking")
	}

	blocked, _ := pe.IsBlocked("skill", "dual-skill")
	if !blocked {
		t.Fatal("expected blocked")
	}
}

func TestPolicyEngineAllowRemovesBlock(t *testing.T) {
	store := newTestStore(t)
	pe := enforce.NewPolicyEngine(store)

	if err := pe.Block("mcp", "https://bad.example.com", "risky"); err != nil {
		t.Fatalf("Block: %v", err)
	}

	if err := pe.Allow("mcp", "https://bad.example.com", "now safe"); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	blocked, _ := pe.IsBlocked("mcp", "https://bad.example.com")
	if blocked {
		t.Fatal("expected not blocked after allowing")
	}

	allowed, _ := pe.IsAllowed("mcp", "https://bad.example.com")
	if !allowed {
		t.Fatal("expected allowed")
	}
}

func TestListBlockedAndAllowed(t *testing.T) {
	store := newTestStore(t)
	pe := enforce.NewPolicyEngine(store)

	_ = pe.Block("skill", "bad-skill-1", "reason 1")
	_ = pe.Block("mcp", "https://bad.example.com", "reason 2")
	_ = pe.Allow("skill", "good-skill-1", "verified")

	blocked, err := pe.ListBlocked()
	if err != nil {
		t.Fatalf("ListBlocked: %v", err)
	}
	if len(blocked) != 2 {
		t.Fatalf("expected 2 blocked, got %d", len(blocked))
	}

	allowed, err := pe.ListAllowed()
	if err != nil {
		t.Fatalf("ListAllowed: %v", err)
	}
	if len(allowed) != 1 {
		t.Fatalf("expected 1 allowed, got %d", len(allowed))
	}
}

func TestSkillEnforcerQuarantineAndRestore(t *testing.T) {
	tmpDir := t.TempDir()
	quarantineDir := filepath.Join(tmpDir, "quarantine")
	skillDir := filepath.Join(tmpDir, "test-skill")

	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "main.py"), []byte("print('hello')"), 0o644); err != nil {
		t.Fatal(err)
	}

	se := enforce.NewSkillEnforcer(quarantineDir)

	dest, err := se.Quarantine(skillDir)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	if _, err := os.Stat(skillDir); !os.IsNotExist(err) {
		t.Fatal("expected original skill directory to be removed after quarantine")
	}

	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("expected quarantine destination to exist: %v", err)
	}

	if !se.IsQuarantined("test-skill") {
		t.Fatal("expected IsQuarantined to return true")
	}

	if err := se.Restore("test-skill", skillDir); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	restoredFile := filepath.Join(skillDir, "main.py")
	data, err := os.ReadFile(restoredFile)
	if err != nil {
		t.Fatalf("expected restored file: %v", err)
	}
	if string(data) != "print('hello')" {
		t.Fatalf("restored content mismatch: %q", string(data))
	}
}

func TestSandboxPolicyDenyAndAllow(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.yaml")

	p := sandbox.DefaultPolicy()
	p.DenyEndpoint("https://bad.example.com")
	p.DenySkill("malicious-skill")

	if err := p.Save(policyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := sandbox.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	if len(loaded.DeniedEndpoints) != 1 || loaded.DeniedEndpoints[0] != "https://bad.example.com" {
		t.Fatalf("expected denied endpoint, got %v", loaded.DeniedEndpoints)
	}
	if len(loaded.DeniedSkills) != 1 || loaded.DeniedSkills[0] != "malicious-skill" {
		t.Fatalf("expected denied skill, got %v", loaded.DeniedSkills)
	}

	loaded.AllowEndpoint("https://bad.example.com")
	loaded.AllowSkill("malicious-skill")

	if len(loaded.DeniedEndpoints) != 0 {
		t.Fatalf("expected no denied endpoints after allow, got %v", loaded.DeniedEndpoints)
	}
	if len(loaded.DeniedSkills) != 0 {
		t.Fatalf("expected no denied skills after allow, got %v", loaded.DeniedSkills)
	}
	if len(loaded.AllowedEndpoints) != 1 {
		t.Fatalf("expected 1 allowed endpoint, got %v", loaded.AllowedEndpoints)
	}
	if len(loaded.AllowedSkills) != 1 {
		t.Fatalf("expected 1 allowed skill, got %v", loaded.AllowedSkills)
	}
}
