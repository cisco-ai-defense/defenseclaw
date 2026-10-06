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

// The digest follows the enforced policy, not how config.yaml wrote it: an
// emptied first_party_allow_list changes it (YAML omits an empty list), and a
// value equal to its default digests like the unset key (GAP-0015, GAP-0032).
func TestEffectivePolicyDigestMaterializesDefaults(t *testing.T) {
	yes := true
	build := func(edit func(*config.Config)) string {
		t.Helper()
		cfg := &config.Config{DataDir: "/home/alice/.defenseclaw"}
		edit(cfg)
		g, err := buildGeneration(context.Background(), generationInputs{cfg: cfg, raw: []byte("config_version: 9\n")})
		if err != nil {
			t.Fatal(err)
		}
		return g.Digest
	}
	base := build(func(*config.Config) {})
	if got := build(func(c *config.Config) { c.Admission.Plugin.FirstPartyAllowList = []config.AdmissionFirstParty{} }); got == base {
		t.Fatal("an emptied admission.plugin.first_party_allow_list left the digest unchanged")
	}
	if got := build(func(c *config.Config) { c.Admission.MCP.ScanOnInstall = &yes }); got != base {
		t.Fatal("admission.mcp.scan_on_install: true (the default) changed the digest")
	}
	withCodex := func(enabled *bool) string {
		return build(func(c *config.Config) {
			c.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {Enabled: enabled}}
		})
	}
	if withCodex(&yes) != withCodex(nil) {
		t.Fatal("guardrail.connectors.codex.enabled: true changed the digest")
	}
}

// A rebuild with the live digest is unchanged only while the Rego policy
// fails (or loads) the same way; a new load failure is published (GAP-0043).
func TestGenerationUnchangedComparesTheOPAFailure(t *testing.T) {
	live := &Generation{Digest: "sha256:a", opaError: "no .rego files found"}
	if !generationUnchanged(live, &Generation{Digest: "sha256:a", opaError: "no .rego files found"}) {
		t.Fatal("an identical rebuild was not unchanged")
	}
	if generationUnchanged(live, &Generation{Digest: "sha256:a", opaError: "parse p0-bad.rego"}) {
		t.Fatal("a new OPA load failure was swallowed as unchanged")
	}
	if generationUnchanged(nil, live) || generationUnchanged(live, &Generation{Digest: "sha256:b", opaError: live.opaError}) {
		t.Fatal("a different generation was unchanged")
	}
}
