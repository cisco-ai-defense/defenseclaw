// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
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
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	kernelcontrols "github.com/defenseclaw/defenseclaw/policies/kernel"
)

func TestConfigDigestNormalizesImplicitLegacySandboxPack(t *testing.T) {
	dataDir, policyDir := t.TempDir(), t.TempDir()
	legacy := filepath.Join(dataDir, "policies", config.DefaultOpenShellPackDirName)
	if err := os.MkdirAll(filepath.Join(legacy, "old-pack"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf("config_version: 9\ndeployment_mode: managed_enterprise\ndata_dir: %q\npolicy_dir: %q\nenterprise:\n  profile: standalone\n", dataDir, policyDir)
	cfg, err := config.LoadRuntimeV8InspectionCandidateFromBytes(filepath.Join(t.TempDir(), "config.yaml"), []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OpenShell.PackDir != legacy {
		t.Fatalf("runtime pack path = %q, want legacy folder %q", cfg.OpenShell.PackDir, legacy)
	}
	canonical, err := cfg.DeepCopy()
	if err != nil {
		t.Fatal(err)
	}
	canonical.OpenShell.PackDir = filepath.Join(policyDir, config.DefaultOpenShellPackDirName)
	scope := newDigestScope(cfg, runtime.GOOS, "")
	legacyDigest, err := configDigest(cfg, scope)
	if err != nil {
		t.Fatal(err)
	}
	canonicalDigest, err := configDigest(canonical, scope)
	if err != nil {
		t.Fatal(err)
	}
	if legacyDigest != canonicalDigest {
		t.Fatalf("implicit legacy pack changed digest: live %s, signer %s", legacyDigest, canonicalDigest)
	}
	canonical.OpenShell.PackDir = filepath.Join(policyDir, "custom-packs")
	explicitDigest, err := configDigest(canonical, scope)
	if err != nil {
		t.Fatal(err)
	}
	if explicitDigest == legacyDigest {
		t.Fatal("an explicit pack path change did not change the digest")
	}
}

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

// A bundle's offline Windows digest and the digest published by a running
// generation must agree for every supported block threshold, including LOW.
func TestBundleAndGatewayDigestForEveryBlockAt(t *testing.T) {
	previous := liveGeneration.Load()
	t.Cleanup(func() { liveGeneration.Store(previous) })
	root := t.TempDir()
	seen := map[string]string{}
	for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		t.Run(level, func(t *testing.T) {
			cfg := &config.Config{ConfigVersion: config.ConfigVersionV9, DataDir: t.TempDir(),
				DeploymentMode: managed.DeploymentModeManagedEnterprise}
			cfg.Enterprise.Profile = managed.ProfileStandalone
			cfg.Guardrail.Enabled = true
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.BlockAt = level
			raw := []byte("config_version: 9\nguardrail:\n  enabled: true\n  mode: action\n  block_at: " + level + "\n")
			bundle, err := ComputeEffectivePolicyFor(context.Background(), cfg,
				EffectivePolicyOptions{GOOS: "windows", BundleRoot: root, Raw: raw})
			if err != nil {
				t.Fatal(err)
			}
			packs, err := generationRulePacks(cfg)
			if err != nil {
				t.Fatal(err)
			}
			profiles, err := newGuardrailProfileSet(cfg, packs.cache, false)
			if err != nil {
				profiles = nil
			}
			generation, err := buildGeneration(context.Background(), generationInputs{
				cfg: cfg, raw: raw, rulePacks: packs, profiles: profiles,
				goos: "windows", bundleRoot: root,
			})
			if err != nil {
				t.Fatal(err)
			}
			liveGeneration.Store(generation)
			reported, ok := CurrentPolicyHealth()
			if !ok || bundle.Digest != reported.EffectiveDigest {
				t.Fatalf("block_at %s: bundle digest %s, gateway digest %s", level, bundle.Digest, reported.EffectiveDigest)
			}
			if earlier, duplicate := seen[bundle.Digest]; duplicate {
				t.Fatalf("block_at %s and %s have the same digest %s", earlier, level, bundle.Digest)
			}
			seen[bundle.Digest] = level
		})
	}
}

// A bundle must not pick up a confidence policy from the signer's or the
// device's runtime directory. Only files shipped in the bundle are signed.
func TestBundleDigestIgnoresHostConfidencePolicy(t *testing.T) {
	root := t.TempDir()
	dataDir := t.TempDir()
	cfg := &config.Config{DataDir: dataDir}
	cfg.AIDiscovery.ConfidencePolicyPath = filepath.Join(dataDir, "confidence.yaml")
	digest := func() EffectivePolicy {
		t.Helper()
		got, err := ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{GOOS: "linux", BundleRoot: root, Raw: []byte("config_version: 8\n")})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	before := digest()
	if err := os.WriteFile(cfg.AIDiscovery.ConfidencePolicyPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after := digest()
	if before.Digest != after.Digest {
		t.Fatalf("host confidence policy changed bundle digest: %s != %s; components before=%v after=%v", before.Digest, after.Digest, before.Components, after.Components)
	}
}

func TestBundleDigestIgnoresExternalRegoAndSignatureFiles(t *testing.T) {
	root, external := t.TempDir(), t.TempDir()
	cfg := &config.Config{DataDir: t.TempDir(), PolicyDir: external}
	cfg.AIDiscovery.SignaturePacks = []string{filepath.Join(external, "signatures.json")}
	digest := func() EffectivePolicy {
		t.Helper()
		got, err := ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{GOOS: "linux", BundleRoot: root, Raw: []byte("config_version: 9\n")})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	before := digest()
	if err := os.WriteFile(cfg.AIDiscovery.SignaturePacks[0], []byte(`{"version":1,"signatures":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	regoDir := filepath.Join(external, "rego")
	if err := os.MkdirAll(regoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"admission.rego", "guardrail.rego"} {
		body, err := os.ReadFile(filepath.Join(repoPolicyDir(t), "rego", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(regoDir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	after := digest()
	if before.Digest != after.Digest {
		t.Fatalf("external Rego or signatures changed bundle digest: %s != %s", before.Digest, after.Digest)
	}
	if _, ok := after.Components["rego"]; ok {
		t.Fatal("external Rego entered bundle components")
	}
}

func TestBundleDigestIgnoresExternalProviderCA(t *testing.T) {
	root, external := t.TempDir(), t.TempDir()
	ca := filepath.Join(external, "ca.pem")
	cfg := &config.Config{ConfigVersion: config.ConfigVersionV9, DataDir: t.TempDir()}
	cfg.LLMProviders.Custom = []config.LLMCustomProvider{{Name: "corp", Domains: []string{"example.com"}, TLS: &config.LLMCustomProviderTLS{CACertFile: ca}}}
	digest := func() EffectivePolicy {
		t.Helper()
		got, err := ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{GOOS: "linux", BundleRoot: root, Raw: []byte("config_version: 9\n")})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	before := digest()
	if err := os.WriteFile(ca, []byte("host-only-ca"), 0o600); err != nil {
		t.Fatal(err)
	}
	after := digest()
	if before.Digest != after.Digest {
		t.Fatalf("external provider CA changed bundle digest: %s != %s", before.Digest, after.Digest)
	}
}

func TestManagedBundleIgnoresPerUserProviderOverlay(t *testing.T) {
	cfg := &config.Config{ConfigVersion: 8, DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	root := t.TempDir()
	digest := func() string {
		t.Helper()
		got, err := ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{GOOS: "linux", BundleRoot: root, Raw: []byte("config_version: 8\n")})
		if err != nil {
			t.Fatal(err)
		}
		return got.Digest
	}
	before := digest()
	overlay := filepath.Join(t.TempDir(), "custom-providers.json")
	if err := os.WriteFile(overlay, []byte(`{"providers":[{"name":"OPENAI","domains":["host-only.example.com"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", overlay)
	if after := digest(); before != after {
		t.Fatalf("per-user provider overlay changed managed bundle digest: %s != %s", before, after)
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
	for _, in := range []string{`C:\ProgramData\DefenseClaw\bundles\v7-0123abcd\discovery\confidence.yaml`, "C:/ProgramData/DefenseClaw/bundles/v7-0123abcd/discovery/confidence.yaml", `c:\programdata\DEFENSECLAW\bundles\v7-0123abcd\discovery\confidence.yaml`} {
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

func TestBundleRuntimeDigestUsesReceiptSpecificInstalledRoot(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	const bundleID = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z2A"
	name := enterprisebundle.VersionDirNameForReceipt(7, bundleID, bundleID)
	bundleRoot := filepath.Join(root, "bundles", name)
	if err := os.MkdirAll(bundleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := []byte("config_version: 9\nplugin_dir: " + filepath.Join(bundleRoot, "plugins") + "\n")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	record := fmt.Sprintf(`{"generation":7,"config_sha256":"%x","actor":"operator:alice","written_at":"2026-10-13T00:00:00Z","bundle_id":%q,"bundle_version":7,"signer_key_id":"k1"}`, sum, bundleID)
	if err := os.WriteFile(filepath.Join(root, "config.generation.json"), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ConfigFilePath: configPath, DataDir: filepath.Join(root, "runtime"), PluginDir: filepath.Join(bundleRoot, "plugins")}
	signed, err := ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{BundleRoot: bundleRoot, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	runtimePolicy, err := ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{Raw: raw})
	if err != nil || runtimePolicy.Digest != signed.Digest {
		t.Fatalf("receipt-specific root digest: signed=%s runtime=%s err=%v", signed.Digest, runtimePolicy.Digest, err)
	}
}

// A settings-only bundle names no file under its version directory, so the
// gateway cannot find its root in config.yaml. It still digests the bundle in
// the bundle scope (without the device's rule packs and the other assets
// outside the bundle), so the digest it reports equals the signed one and the
// apply confirms (GAP-0158). A bundle that names a bundle file already agreed;
// a config with no bundle record keeps every rule pack in its digest.
func TestBundleRuntimeDigestScopesSettingsOnlyBundle(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	srcPack := filepath.Join(filepath.Dir(here), "..", "..", "policies", "guardrail", "default")
	const bundleID = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z2A"
	for _, namesFile := range []bool{false, true} {
		name := "settings_only"
		if namesFile {
			name = "names_bundle_file"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "config.yaml")
			bundleRoot := filepath.Join(root, "bundles", enterprisebundle.VersionDirNameForReceipt(101, bundleID, bundleID))
			signRoot := t.TempDir()
			for _, r := range []string{bundleRoot, signRoot} {
				if err := os.MkdirAll(filepath.Join(r, "discovery"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(r, "discovery", "confidence.yaml"), []byte("version: 1\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.CopyFS(filepath.Join(root, "runtime", "policies", "guardrail", "default"), os.DirFS(srcPack)); err != nil {
				t.Fatal(err)
			}
			body := func(r string) []byte {
				extra := ""
				if namesFile {
					extra = "ai_discovery:\n  confidence_policy_path: " + filepath.Join(r, "discovery", "confidence.yaml") + "\n"
				}
				return []byte("config_version: 9\ndata_dir: " + filepath.Join(root, "runtime") + "\n" + extra +
					"guardrail:\n  enabled: true\n  mode: action\n  block_at: MEDIUM\n  connectors:\n    codex: {}\n    claudecode: {}\n")
			}
			rawDevice, rawSigner := body(bundleRoot), body(signRoot)
			if err := os.WriteFile(configPath, rawDevice, 0o600); err != nil {
				t.Fatal(err)
			}
			writeRecord := func(bundle bool) {
				t.Helper()
				sum := sha256.Sum256(rawDevice)
				fields := `"actor":"operator:alice"`
				if bundle {
					fields = fmt.Sprintf(`"actor":"bundle:%s","bundle_id":%q,"bundle_version":101,"signer_key_id":"k1"`, bundleID, bundleID)
				}
				record := fmt.Sprintf(`{"generation":35,"config_sha256":"%x","written_at":"2026-10-18T00:00:00Z",%s}`, sum, fields)
				if err := os.WriteFile(filepath.Join(root, "config.generation.json"), []byte(record), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeRecord(true)
			load := func(raw []byte) *config.Config {
				t.Helper()
				cfg, err := config.LoadRuntimeV8InspectionCandidateFromBytes(configPath, raw)
				if err != nil {
					t.Fatalf("load: %v", err)
				}
				return cfg
			}
			signed, err := ComputeEffectivePolicyFor(context.Background(), load(rawSigner), EffectivePolicyOptions{BundleRoot: signRoot, Raw: rawSigner})
			if err != nil {
				t.Fatal(err)
			}
			// The running gateway and `policy digest` pass no bundle root.
			gw, err := ComputeEffectivePolicyFor(context.Background(), load(rawDevice), EffectivePolicyOptions{Raw: rawDevice})
			if err != nil {
				t.Fatal(err)
			}
			if signed.Digest != gw.Digest {
				t.Fatalf("signed digest %s != gateway digest %s\nsigned=%v\ngateway=%v", signed.Digest, gw.Digest, signed.Components, gw.Components)
			}
			for key := range gw.Components {
				if strings.HasPrefix(key, "rule_pack:") {
					t.Fatalf("bundle digest kept the device rule pack %s: %v", key, gw.Components)
				}
			}
			if namesFile {
				return
			}
			writeRecord(false)
			plain, err := ComputeEffectivePolicyFor(context.Background(), load(rawDevice), EffectivePolicyOptions{Raw: rawDevice})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := plain.Components["rule_pack:global"]; !ok || plain.Digest == gw.Digest {
				t.Fatalf("a config with no bundle record lost its rule packs: digest=%s components=%v", plain.Digest, plain.Components)
			}
		})
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
	if generationUnchanged(live, &Generation{Digest: live.Digest, opaError: live.opaError, BundleID: "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8", BundleVersion: 2}) {
		t.Fatal("a new signed bundle was swallowed as an unchanged asset rebuild")
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

	// A glob with a wildcard folder is watched at its fixed folder and at
	// each folder it matches: a new matching folder rebuilds and is
	// watched, then a pack created in it rebuilds again (GAP-0858).
	entry := filepath.Join(packs, "*", "pack.json")
	cfg.AIDiscovery.SignaturePacks = []string{entry}
	live = &Generation{Components: assetDigestComponents(cfg, newDigestScope(cfg, "", ""))}
	if !slices.Contains(generationAssetDirs(cfg, &Generation{}), packs) || discoveryAssetsChanged(live, cfg) {
		t.Fatalf("%s: the fixed folder is not watched, or an untouched entry rebuilt discovery", entry)
	}
	team := filepath.Join(packs, "team")
	if err := os.Mkdir(team, 0o700); err != nil {
		t.Fatal(err)
	}
	if !discoveryAssetsChanged(live, cfg) || !slices.Contains(generationAssetDirs(cfg, &Generation{}), team) {
		t.Fatalf("%s: a new matching folder did not rebuild discovery or is not watched", entry)
	}
	live = &Generation{Components: assetDigestComponents(cfg, newDigestScope(cfg, "", ""))}
	if err := os.WriteFile(filepath.Join(team, "pack.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !discoveryAssetsChanged(live, cfg) {
		t.Fatalf("%s: a pack in the new folder did not rebuild discovery", entry)
	}
}

// livePolicyStampPresent reports whether records outside a request would carry
// a policy stamp.
func livePolicyStampPresent() bool {
	digest, generation := livePolicyStampV8()
	return digest.IsPresent() || generation.IsPresent()
}
