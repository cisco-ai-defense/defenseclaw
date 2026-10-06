// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestEffectivePolicyDigestAndHealth covers effective_policy_digest: two
// users with the same policy get the same digest (secrets are dropped and
// data_dir paths rewritten), a policy change moves it, and /health publishes
// the live generation in "policy", except under the Secure Client
// integration, whose /health is unchanged.
func TestEffectivePolicyDigestAndHealth(t *testing.T) {
	policyDir := repoPolicyDir(t)
	build := func(dataDir, token, blockAt string, edits ...func(*config.Config)) *Generation {
		t.Helper()
		cfg := &config.Config{PolicyDir: policyDir, DataDir: dataDir}
		for _, edit := range edits {
			edit(cfg)
		}
		cfg.Gateway.Token = token
		cfg.AIDiscovery.ConfidencePolicyPath = filepath.Join(dataDir, "confidence.yaml")
		cfg.Guardrail.RulePack = "default"
		cfg.Guardrail.BlockAt = blockAt
		global, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "global")
		if err != nil {
			t.Fatal(err)
		}
		g, err := buildGeneration(context.Background(), generationInputs{
			cfg: cfg, rulePacks: &sidecarRulePackCandidate{global: global, active: global},
		})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	alice := build("/home/alice/.defenseclaw", "token-a", "")
	bob := build("/home/bob/.defenseclaw", "token-b", "")
	if alice.Digest != bob.Digest {
		t.Fatalf("same policy, different users: %s != %s (components %v vs %v)", alice.Digest, bob.Digest, alice.Components, bob.Components)
	}
	if strict := build("/home/alice/.defenseclaw", "token-a", "HIGH"); strict.Digest == alice.Digest {
		t.Fatal("guardrail.block_at did not change the effective digest")
	}
	// Unset keeps the built-in first-party plugin, [] clears it: different
	// enforcement, so a different digest (GAP-0028).
	cleared := build("/home/alice/.defenseclaw", "token-a", "", func(cfg *config.Config) {
		cfg.Admission.Plugin.FirstPartyAllowList = []config.AdmissionFirstParty{}
	})
	if cleared.Digest == alice.Digest {
		t.Fatal("an empty admission.plugin.first_party_allow_list left the effective digest unchanged")
	}

	prev := liveGeneration.Load()
	t.Cleanup(func() { liveGeneration.Store(prev) })
	health := func() map[string]json.RawMessage {
		t.Helper()
		rec := httptest.NewRecorder()
		(&APIServer{health: NewSidecarHealth()}).handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	liveGeneration.Store(alice)
	var policy PolicyHealth
	if err := json.Unmarshal(health()["policy"], &policy); err != nil || policy.EffectiveDigest != alice.Digest {
		t.Fatalf("/health policy = %+v (%v), want digest %s", policy, err, alice.Digest)
	}
	alice.Config.DeploymentMode = "managed_enterprise"
	alice.Config.Enterprise.Profile = managed.ProfileSecureClient
	if _, ok := health()["policy"]; ok || livePolicyDigestV8().IsPresent() {
		t.Fatal("the Secure Client integration's /health or decision records carry the effective policy")
	}
}

// The observability section (retention, destinations, redaction) is part of
// the effective digest, with data_dir paths rewritten (GAP-0007).
func TestEffectivePolicyDigestCoversObservability(t *testing.T) {
	build := func(dataDir, section string) string {
		t.Helper()
		g, err := buildGeneration(context.Background(), generationInputs{
			cfg: &config.Config{DataDir: dataDir},
			raw: []byte("config_version: 9\nobservability:\n" + section),
		})
		if err != nil {
			t.Fatal(err)
		}
		return g.Digest
	}
	base := build("/home/alice/.defenseclaw", "  local:\n    retention_days: 7\n")
	if build("/home/alice/.defenseclaw", "  local:\n    retention_days: 1\n") == base {
		t.Fatal("observability.local.retention_days did not change the effective digest")
	}
	if build("/home/bob/.defenseclaw", "  local:\n    retention_days: 7\n") != base {
		t.Fatal("the same observability policy under another data_dir changed the digest")
	}
	alicePath := build("/home/alice/.defenseclaw", "  local:\n    path: /home/alice/.defenseclaw/audit.db\n")
	if alicePath != build("/home/bob/.defenseclaw", "  local:\n    path: /home/bob/.defenseclaw/audit.db\n") {
		t.Fatal("a store path under data_dir differs between users")
	}
}
