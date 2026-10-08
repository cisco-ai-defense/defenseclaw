// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestValidateGuardrailProfiles(t *testing.T) {
	enabled := true
	valid := func() GuardrailConfig {
		return GuardrailConfig{
			Profiles: map[string]GuardrailProfile{
				"contractors": {Mode: "action", BlockAt: "medium", Connectors: map[string]PerConnectorGuardrailConfig{"codex": {Mode: "observe"}}},
			},
			ProfileAssignments: []ProfileAssignment{
				{Profile: "contractors", Match: ProfileMatch{Groups: []string{`CORP\Contractors`}}},
			},
			DefaultProfile: "contractors",
		}
	}
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "valid", mutate: func(*Config) {}},
		{name: "unknown assignment profile", mutate: func(c *Config) { c.Guardrail.ProfileAssignments[0].Profile = "ml-team" }, want: `unknown profile "ml-team"`},
		{name: "unknown default profile", mutate: func(c *Config) { c.Guardrail.DefaultProfile = "ml-team" }, want: `default_profile: unknown profile`},
		{name: "enabled in profile", mutate: func(c *Config) {
			p := c.Guardrail.Profiles["contractors"]
			p.Enabled = &enabled
			c.Guardrail.Profiles["contractors"] = p
		}, want: "enabled is not allowed in a guardrail profile"},
		{name: "hook_fail_mode in profile connector", mutate: func(c *Config) {
			c.Guardrail.Profiles["contractors"].Connectors["codex"] = PerConnectorGuardrailConfig{HookFailMode: "open"}
		}, want: `connectors["codex"]: hook_fail_mode is not allowed`},
		{name: "secure client", mutate: func(c *Config) {
			c.DeploymentMode = "managed_enterprise"
			c.Enterprise.Profile = "secure_client"
		}, want: "not supported with the Secure Client integration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Guardrail: valid()}
			tc.mutate(cfg)
			err := cfg.ValidateGuardrailProfiles()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateGuardrailProfiles() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateGuardrailProfiles() = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func profileDerivationFixture() *Config {
	cfg := &Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.HookFailMode = "closed"
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{
		"codex":  {Mode: "action", BlockAt: "HIGH"},
		"cursor": {},
	}
	cfg.ClaudeCode.Mode = "action"
	cfg.ApplicationProtection.Enabled = true
	cfg.ApplicationProtection.Guardrail = PerConnectorGuardrailConfig{Mode: "action"}
	cfg.ApplicationProtection.Connectors = map[string]ApplicationProtectionConnectorConfig{
		"amp": {Guardrail: PerConnectorGuardrailConfig{Mode: "action"}},
	}
	cfg.Guardrail.Profiles = map[string]GuardrailProfile{
		"watch": {
			Mode: "observe", BlockAt: "low", HILT: &HILTConfig{Enabled: true, MinSeverity: "HIGH"},
			Connectors: map[string]PerConnectorGuardrailConfig{
				"codex": {Mode: "action"},
				"amp":   {BlockAt: "CRITICAL"},
				"kiro":  {Mode: "action"},
			},
		},
	}
	return cfg
}

// TestDerivedForProfilePrecedence pins profile.connectors[c] > profile field
// > guardrail.connectors[c] > application_protection overlay > global, for
// manual connectors (codex, cursor) and automatically protected ones (amp,
// kiro, opencode), and that the base configuration and connector membership
// are left alone.
func TestDerivedForProfilePrecedence(t *testing.T) {
	base := profileDerivationFixture()
	derived, err := base.DerivedForProfile("watch")
	if err != nil {
		t.Fatalf("DerivedForProfile: %v", err)
	}
	cases := []struct {
		connector, mode, blockAt string
	}{
		{"codex", "action", "LOW"},     // profile.connectors mode; profile block_at over connectors[codex]
		{"cursor", "observe", "LOW"},   // profile field over the global
		{"amp", "observe", "CRITICAL"}, // profile field over the AP overlay; profile.connectors block_at
		{"kiro", "action", "LOW"},      // profile.connectors over the AP overlay
		{"opencode", "observe", "LOW"}, // profile field written over application_protection.guardrail
	}
	for _, tc := range cases {
		if got := derived.EffectiveGuardrailModeForConnector(tc.connector); got != tc.mode {
			t.Errorf("%s mode = %q, want %q", tc.connector, got, tc.mode)
		}
		if got := derived.Guardrail.EffectiveBlockAt(tc.connector); got != tc.blockAt {
			t.Errorf("%s block_at = %q, want %q", tc.connector, got, tc.blockAt)
		}
		if got := derived.EffectiveHILTForConnector(tc.connector); !got.Enabled {
			t.Errorf("%s hilt = %+v, want the profile's", tc.connector, got)
		}
		if got, want := derived.EffectiveHookFailModeForConnector(tc.connector), base.EffectiveHookFailModeForConnector(tc.connector); tc.connector == "codex" && got != want {
			t.Errorf("%s hook_fail_mode = %q, want base %q", tc.connector, got, want)
		}
	}
	if derived.ClaudeCode.Mode != "" {
		t.Errorf("profile mode must replace claude_code.mode, got %q", derived.ClaudeCode.Mode)
	}
	if derived.Guardrail.HasConnector("kiro") || len(derived.ActiveConnectors()) != 2 {
		t.Errorf("a profile must not change connector membership: %v", derived.ActiveConnectors())
	}
	if got := base.EffectiveGuardrailModeForConnector("cursor"); got != "action" {
		t.Errorf("base cursor mode = %q after derivation, want action", got)
	}
	if got := base.Guardrail.EffectiveBlockAt("codex"); got != "HIGH" {
		t.Errorf("base codex block_at = %q after derivation, want HIGH", got)
	}
	if _, err := base.DerivedForProfile("missing"); err == nil {
		t.Error("DerivedForProfile(missing) = nil error, want an error")
	}
	// A derived configuration reads the base's profile table: copying it
	// into every derived configuration made deriving P profiles quadratic
	// in P (GAP-0118: 2000 profiles took 68 s at every start and reload).
	if reflect.ValueOf(derived.Guardrail.Profiles).Pointer() != reflect.ValueOf(base.Guardrail.Profiles).Pointer() || len(derived.Guardrail.Profiles) != 1 {
		t.Error("the derived configuration copied the profile table instead of sharing it")
	}
}

// TestGuardrailPolicyDigestStable pins the digest format and that it depends
// only on the derived policy: equal across derivations, different after an
// edit, and blind to the guardrail LLM credential.
func TestGuardrailPolicyDigestStable(t *testing.T) {
	digestOf := func(cfg *Config) string {
		t.Helper()
		profiles, err := cfg.DeriveGuardrailProfiles()
		if err != nil {
			t.Fatalf("DeriveGuardrailProfiles: %v", err)
		}
		return profiles["watch"].Digest
	}
	first := digestOf(profileDerivationFixture())
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(first) {
		t.Fatalf("digest %q does not match sha256:<64 hex>", first)
	}
	for i := 0; i < 5; i++ {
		if again := digestOf(profileDerivationFixture()); again != first {
			t.Fatalf("digest changed between derivations: %s != %s", again, first)
		}
	}
	secret := profileDerivationFixture()
	secret.Guardrail.LLM.APIKey = "not-a-real-key"
	if got := digestOf(secret); got != first {
		t.Errorf("digest depends on the guardrail LLM key")
	}
	edited := profileDerivationFixture()
	p := edited.Guardrail.Profiles["watch"]
	p.AlertAt = "LOW"
	edited.Guardrail.Profiles["watch"] = p
	if got := digestOf(edited); got == first {
		t.Errorf("digest unchanged after a profile edit")
	}
}

// GAP-0276: every gateway start and reload derives all profiles. With 1,000
// profiles the configuration was copied once per profile (a JSON round trip
// each); it is copied once, and each profile owns only the maps it changes.
func TestDeriveGuardrailProfilesCopiesTheConfigurationOnce(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {Mode: "observe"}}
	// A section no profile changes, large enough that copying it per
	// profile shows.
	cfg.AIDiscovery.SignaturePackDigests = make(map[string]string, 200)
	for i := range 200 {
		cfg.AIDiscovery.SignaturePackDigests[fmt.Sprintf("/packs/p%03d.json", i)] = "sha256:00"
	}
	cfg.Guardrail.Profiles = make(map[string]GuardrailProfile, 1000)
	for i := range 1000 {
		cfg.Guardrail.Profiles[fmt.Sprintf("scale-%04d", i)] = GuardrailProfile{
			Mode:       "action",
			Connectors: map[string]PerConnectorGuardrailConfig{"claudecode": {Mode: "observe"}},
		}
	}
	var derived map[string]DerivedGuardrailProfile
	allocs := testing.AllocsPerRun(1, func() {
		var err error
		if derived, err = cfg.DeriveGuardrailProfiles(); err != nil {
			t.Fatal(err)
		}
	})
	if len(derived) != 1000 || derived["scale-0007"].Config.Guardrail.Mode != "action" ||
		derived["scale-0007"].Config.Guardrail.Connectors["codex"].Mode != "action" {
		t.Fatalf("derived profile = %+v", derived["scale-0007"].Config.Guardrail)
	}
	if cfg.Guardrail.Connectors["codex"].Mode != "observe" {
		t.Fatal("deriving a profile changed the base connector override")
	}
	if per := allocs / 1000; per > 100 {
		t.Fatalf("deriving 1,000 profiles made %.0f allocations per profile; copy the configuration once", per)
	}
}
