// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	kernelcontrols "github.com/defenseclaw/defenseclaw/policies/kernel"
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
	if _, ok := health()["policy"]; ok || livePolicyStampPresent() {
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
		got, err := configDigest(cfg, newDigestScope(cfg, "", ""))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(cfg.Enterprise.Tetragon, block) {
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
			{Mode: "consume", BurnIn: "0168h", EnforceAck: config.TetragonEnforceAcks{" "}},
			{CustomerEvents: "agent"},
			{EnforceAck: config.TetragonEnforceAcks{}},
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
			{Mode: "enforce", EnforceAck: config.TetragonEnforceAcks{"sha256:3f9c2a7d41b0"}},
			{Mode: "enforce", EnforceAck: config.TetragonEnforceAcks{"sha256:3f9c2a7d41b0", "sha256:08b71155b713"}},
			{BurnIn: "24h"},
			{BurnIn: "0"},
			{CustomerEvents: "off"},
		} {
			got := digest(different, profile)
			if previous, dup := seen[got]; dup {
				t.Errorf("profile %q: %+v and %+v digest the same", profile, different, previous)
			}
			seen[got] = different
		}
	}
}

// TestKernelPolicyComponent: the kernel_policy component is the sensor
// helper's short kernel_policy digest (the value enforce_ack approves), and it
// is present only where the helper loads the controls: a Linux standalone
// deployment whose effective Tetragon mode is observe or enforce.
func TestKernelPolicyComponent(t *testing.T) {
	build := func(profile, mode string, planeC bool) *config.Config {
		cfg := &config.Config{DeploymentMode: "managed_enterprise"}
		cfg.Enterprise.Profile = profile
		cfg.Enterprise.Tetragon = config.EnterpriseTetragonConfig{Mode: mode}
		cfg.AIDiscovery.Runtime = config.AIRuntimeConfig{Enabled: true, EnableHostPlane: planeC}
		return cfg
	}
	standalone := managed.ProfileStandalone
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		goos string
		want bool
	}{
		{"observe", build(standalone, "observe", true), "linux", true},
		{"enforce", build(standalone, "enforce", true), "linux", true},
		{"default consume", build(standalone, "", true), "linux", false},
		{"consume", build(standalone, "consume", true), "linux", false},
		{"off", build(standalone, "off", true), "linux", false},
		{"plane c off", build(standalone, "enforce", false), "linux", false},
		{"macos", build(standalone, "enforce", true), "darwin", false},
		{"windows", build(standalone, "observe", true), "windows", false},
		{"secure client", build(managed.ProfileSecureClient, "observe", true), "linux", false},
		{"unmanaged", &config.Config{}, "linux", false},
		{"nil", nil, "linux", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ""
			if tc.want {
				want = kernelcontrols.Digest()
			}
			if got := kernelPolicyComponent(tc.cfg, tc.goos); got != want {
				t.Fatalf("kernelPolicyComponent = %q, want %q", got, want)
			}
		})
	}
	if got := kernelPolicyComponent(build(standalone, "observe", true), "linux"); !kernelcontrols.AckMatches(got) {
		t.Fatalf("component %q is not the value enforce_ack approves", got)
	}
	// The digest scope names the platform, so every host computes the
	// Linux component the same way (bundle sign digests each target).
	linux, darwin := newDigestScope(nil, "linux", ""), newDigestScope(nil, "darwin", "")
	if got := assetDigestComponents(build(standalone, "enforce", true), linux)["kernel_policy"]; got != kernelcontrols.Digest() {
		t.Fatalf("assetDigestComponents kernel_policy = %q, want %q", got, kernelcontrols.Digest())
	}
	if got, ok := assetDigestComponents(build(standalone, "enforce", true), darwin)["kernel_policy"]; ok {
		t.Fatalf("the darwin scope carries a kernel_policy component %q", got)
	}
	if got, ok := assetDigestComponents(build(standalone, "consume", true), linux)["kernel_policy"]; ok {
		t.Fatalf("consume carries a kernel_policy component %q", got)
	}
}

// TestDigestScopeRewrite: a path under the policy bundle root digests as
// ${bundle_root}/..., one under data_dir as ${data_dir}/...; the bundle root
// wins when it lies inside data_dir, a sibling with the same prefix is not
// rewritten, and a Windows path written with either separator matches.
func TestDigestScopeRewrite(t *testing.T) {
	cfg := &config.Config{DataDir: "/var/lib/defenseclaw"}
	scope := newDigestScope(cfg, "linux", "/var/lib/defenseclaw/bundles/v7-0123abcd/")
	for in, want := range map[string]string{
		"/var/lib/defenseclaw/bundles/v7-0123abcd/policies/guardrail/p": "${bundle_root}/policies/guardrail/p",
		"/var/lib/defenseclaw/bundles/v7-0123abcd":                      "${bundle_root}",
		"/var/lib/defenseclaw/bundles/v7-0123abcdX/p":                   "${data_dir}/bundles/v7-0123abcdX/p",
		"/var/lib/defenseclaw/audit.db":                                 "${data_dir}/audit.db",
		"/etc/defenseclaw/policies":                                     "/etc/defenseclaw/policies",
		"policies/guardrail/p":                                          "policies/guardrail/p",
	} {
		if got := scope.rewrite(in); got != want {
			t.Errorf("rewrite(%q) = %q, want %q", in, got, want)
		}
	}
	windows := newDigestScope(&config.Config{}, "windows", `C:\ProgramData\DefenseClaw\bundles\v7-0123abcd`)
	for _, in := range []string{`C:\ProgramData\DefenseClaw\bundles\v7-0123abcd\discovery\confidence.yaml`, "C:/ProgramData/DefenseClaw/bundles/v7-0123abcd/discovery/confidence.yaml"} {
		if runtime.GOOS != "windows" {
			break // filepath.ToSlash maps backslashes on Windows only
		}
		if got := windows.rewrite(in); got != "${bundle_root}/discovery/confidence.yaml" {
			t.Errorf("rewrite(%q) = %q", in, got)
		}
	}
}

func TestHealthBoundsManyPolicyComponents(t *testing.T) {
	prev := liveGeneration.Load()
	t.Cleanup(func() { liveGeneration.Store(prev) })
	components := make(map[string]string, 2000)
	for i := 0; i < 2000; i++ {
		components[fmt.Sprintf("profile:%04d", i)] = strings.Repeat("a", 64)
	}
	liveGeneration.Store(&Generation{
		Config: &config.Config{}, Digest: "sha256:effective", Components: components,
	})
	rec := httptest.NewRecorder()
	(&APIServer{health: NewSidecarHealth()}).handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() > 65536 {
		t.Fatalf("/health status=%d, size=%d; want bounded response", rec.Code, rec.Body.Len())
	}
	var body struct {
		Policy struct {
			EffectiveDigest string            `json:"effective_digest"`
			ComponentCount  int               `json:"component_count"`
			Components      map[string]string `json:"components"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Policy.EffectiveDigest != "sha256:effective" || body.Policy.ComponentCount != len(components) || len(body.Policy.Components) != 0 {
		t.Fatalf("/health policy = %+v", body.Policy)
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
	// The levels take any case (GAP-0329): high and HIGH are one policy.
	level := func(global, codex string) string {
		return build(func(c *config.Config) {
			c.Guardrail.BlockAt = global
			c.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {AlertAt: codex}}
		})
	}
	if level("high", "medium") != level("HIGH", "MEDIUM") {
		t.Fatal("guardrail.block_at high and HIGH (or a connector's alert_at medium and MEDIUM) gave two digests")
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

// A signature pack edited on disk rebuilds AI discovery, which loads its catalog
// once: under a pin it no longer matches, the pack is refused at once instead of
// at the next config change (GAP-0177). The confidence policy file, loaded
// once too, rebuilds it the same way when it is created or edited (GAP-0316).
func TestDiscoveryAssetsChangedFollowsTheFileNotTheConfig(t *testing.T) {
	pack := filepath.Join(t.TempDir(), "pack.json")
	if err := os.WriteFile(pack, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.AIDiscovery.Enabled = true
	cfg.AIDiscovery.SignaturePacks = []string{pack}
	live := &Generation{Components: assetDigestComponents(cfg, newDigestScope(cfg, "", ""))}
	if discoveryAssetsChanged(live, cfg) {
		t.Fatal("an untouched pack rebuilt discovery")
	}
	if err := os.WriteFile(pack, []byte(`{"version":1,"signatures":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !discoveryAssetsChanged(live, cfg) {
		t.Fatal("an edited pack did not rebuild discovery")
	}
	live = &Generation{Components: assetDigestComponents(cfg, newDigestScope(cfg, "", ""))}
	cfg.AIDiscovery.ConfidencePolicyPath = filepath.Join(cfg.DataDir, "confidence.yaml")
	if discoveryAssetsChanged(live, cfg) {
		t.Fatal("an absent confidence policy rebuilt discovery")
	}
	if err := os.WriteFile(cfg.AIDiscovery.ConfidencePolicyPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !discoveryAssetsChanged(live, cfg) {
		t.Fatal("a new confidence policy did not rebuild discovery")
	}
	cfg.AIDiscovery.Enabled = false
	if discoveryAssetsChanged(live, cfg) {
		t.Fatal("a disabled discovery service was rebuilt for a pack edit")
	}

	// A directory or glob entry follows the packs it names: a new pack
	// rebuilds discovery, and the entry is watched.
	packs := t.TempDir()
	for _, entry := range []string{packs, filepath.Join(packs, "*.json")} {
		cfg.AIDiscovery.Enabled = true
		cfg.AIDiscovery.SignaturePacks = []string{entry}
		live = &Generation{Components: assetDigestComponents(cfg, newDigestScope(cfg, "", ""))}
		if discoveryAssetsChanged(live, cfg) {
			t.Fatalf("%s: an untouched entry rebuilt discovery", entry)
		}
		added := filepath.Join(packs, "added.json")
		if err := os.WriteFile(added, []byte(`{"version":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if !discoveryAssetsChanged(live, cfg) {
			t.Fatalf("%s: a new pack did not rebuild discovery", entry)
		}
		if !slices.Contains(generationAssetDirs(cfg, &Generation{}), packs) {
			t.Fatalf("%s: the folder is not watched", entry)
		}
		if err := os.Remove(added); err != nil {
			t.Fatal(err)
		}
	}
}

// livePolicyStampPresent reports whether records outside a request would carry
// a policy stamp.
func livePolicyStampPresent() bool {
	digest, generation := livePolicyStampV8()
	return digest.IsPresent() || generation.IsPresent()
}
