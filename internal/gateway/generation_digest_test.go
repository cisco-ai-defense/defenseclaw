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
	build := func(dataDir, token, blockAt string) *Generation {
		t.Helper()
		cfg := &config.Config{PolicyDir: policyDir, DataDir: dataDir}
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

// TestConfigDigestNormalizesTetragonDefaults: an absent enterprise.tetragon
// block and one that spells out the defaults are the same intent, so they
// give the same config digest; any other value moves it, and digesting never
// changes the config itself.
func TestConfigDigestNormalizesTetragonDefaults(t *testing.T) {
	digest := func(block config.EnterpriseTetragonConfig, profile string) string {
		t.Helper()
		cfg := &config.Config{DeploymentMode: "managed_enterprise", DataDir: "/var/lib/defenseclaw"}
		cfg.Enterprise.Profile = profile
		cfg.Enterprise.Tetragon = block
		got, err := configDigest(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Enterprise.Tetragon != block {
			t.Fatalf("configDigest changed the config: %+v, want %+v", cfg.Enterprise.Tetragon, block)
		}
		return got
	}
	for _, profile := range []string{managed.ProfileStandalone, ""} {
		absent := digest(config.EnterpriseTetragonConfig{}, profile)
		for _, same := range []config.EnterpriseTetragonConfig{
			{Mode: "consume", BurnIn: "168h"},
			{Mode: "consume"},
			{BurnIn: "168h"},
			{Mode: "consume", BurnIn: "0168h", EnforceAck: " "},
		} {
			if got := digest(same, profile); got != absent {
				t.Errorf("profile %q: %+v digests %s, the absent block %s", profile, same, got, absent)
			}
		}
		seen := map[string]config.EnterpriseTetragonConfig{absent: {}}
		for _, different := range []config.EnterpriseTetragonConfig{
			{Mode: "off"},
			{Mode: "observe"},
			{Mode: "enforce"},
			{Mode: "enforce", EnforceAck: "sha256:3f9c2a7d41b0"},
			{BurnIn: "24h"},
			{BurnIn: "0"},
		} {
			got := digest(different, profile)
			if previous, dup := seen[got]; dup {
				t.Errorf("profile %q: %+v and %+v digest the same", profile, different, previous)
			}
			seen[got] = different
		}
	}
}
