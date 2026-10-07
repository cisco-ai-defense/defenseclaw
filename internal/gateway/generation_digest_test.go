// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
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
	if runtime.GOOS != "linux" {
		return
	}
	if got := assetDigestComponents(build(standalone, "enforce", true))["kernel_policy"]; got != kernelcontrols.Digest() {
		t.Fatalf("assetDigestComponents kernel_policy = %q, want %q", got, kernelcontrols.Digest())
	}
	if got, ok := assetDigestComponents(build(standalone, "consume", true))["kernel_policy"]; ok {
		t.Fatalf("consume carries a kernel_policy component %q", got)
	}
}
