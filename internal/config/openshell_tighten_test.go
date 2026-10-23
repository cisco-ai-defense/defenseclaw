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

package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func bp(v bool) *bool { return &v }

// TestTightenOpenShellAdminCombineMatrix pins plan §5.2: one row per key and
// combination of unset, looser and stricter values.
func TestTightenOpenShellAdminCombineMatrix(t *testing.T) {
	cases := []struct {
		name          string
		base, overlay OpenShellAdminConfig
		want          OpenShellAdminConfig
	}{
		{"allowed false wins", OpenShellAdminConfig{Allowed: bp(true)}, OpenShellAdminConfig{Allowed: bp(false)}, OpenShellAdminConfig{Allowed: bp(false)}},
		{"allowed never loosens", OpenShellAdminConfig{Allowed: bp(false)}, OpenShellAdminConfig{Allowed: bp(true)}, OpenShellAdminConfig{Allowed: bp(false)}},
		{"allow_mount unset base", OpenShellAdminConfig{}, OpenShellAdminConfig{AllowMount: bp(false)}, OpenShellAdminConfig{AllowMount: bp(false)}},
		{"allow_yolo stays false", OpenShellAdminConfig{AllowYolo: bp(false)}, OpenShellAdminConfig{AllowYolo: bp(true)}, OpenShellAdminConfig{AllowYolo: bp(false)}},
		{"telemetry unset base never loosens", OpenShellAdminConfig{}, OpenShellAdminConfig{AllowUpstreamTelemetry: bp(true)}, OpenShellAdminConfig{}},
		{"telemetry true base, false overlay", OpenShellAdminConfig{AllowUpstreamTelemetry: bp(true)}, OpenShellAdminConfig{AllowUpstreamTelemetry: bp(false)}, OpenShellAdminConfig{AllowUpstreamTelemetry: bp(false)}},
		{"telemetry true base kept", OpenShellAdminConfig{AllowUpstreamTelemetry: bp(true)}, OpenShellAdminConfig{}, OpenShellAdminConfig{AllowUpstreamTelemetry: bp(true)}},
		{"process_tree true wins", OpenShellAdminConfig{ProcessTree: bp(false)}, OpenShellAdminConfig{ProcessTree: bp(true)}, OpenShellAdminConfig{ProcessTree: bp(true)}},
		{"process_tree never off", OpenShellAdminConfig{ProcessTree: bp(true)}, OpenShellAdminConfig{ProcessTree: bp(false)}, OpenShellAdminConfig{ProcessTree: bp(true)}},
		{"block_large_uploads or", OpenShellAdminConfig{}, OpenShellAdminConfig{BlockLargeUploads: true}, OpenShellAdminConfig{BlockLargeUploads: true}},
		{"min_profile stricter", OpenShellAdminConfig{MinProfile: "balanced"}, OpenShellAdminConfig{MinProfile: "strict"}, OpenShellAdminConfig{MinProfile: "strict"}},
		{"min_profile never looser", OpenShellAdminConfig{MinProfile: "strict"}, OpenShellAdminConfig{MinProfile: "open"}, OpenShellAdminConfig{MinProfile: "strict"}},
		{"required_pack replaced with its digest", OpenShellAdminConfig{RequiredPack: "balanced", RequiredPackDigest: "sha256:aa"},
			OpenShellAdminConfig{RequiredPack: "strict"}, OpenShellAdminConfig{RequiredPack: "strict"}},
		{"required_pack kept", OpenShellAdminConfig{RequiredPack: "strict", RequiredPackDigest: "sha256:aa"}, OpenShellAdminConfig{},
			OpenShellAdminConfig{RequiredPack: "strict", RequiredPackDigest: "sha256:aa"}},
		// GAP-0115: naming the base's own pack never drops its pin.
		{"same required_pack keeps the base digest", OpenShellAdminConfig{RequiredPack: "/p/contractors/pack.yaml", RequiredPackDigest: "sha256:aa"},
			OpenShellAdminConfig{RequiredPack: "/p/contractors/pack.yaml"},
			OpenShellAdminConfig{RequiredPack: "/p/contractors/pack.yaml", RequiredPackDigest: "sha256:aa"}},
		{"same required_pack by its directory keeps the base digest", OpenShellAdminConfig{RequiredPack: "/p/contractors/pack.yaml", RequiredPackDigest: "sha256:aa"},
			OpenShellAdminConfig{RequiredPack: " /p/x/../contractors/ "},
			OpenShellAdminConfig{RequiredPack: "/p/contractors/pack.yaml", RequiredPackDigest: "sha256:aa"}},
		{"same required_pack name keeps the base digest", OpenShellAdminConfig{RequiredPack: "acme-dev", RequiredPackDigest: "sha256:aa"},
			OpenShellAdminConfig{RequiredPack: "acme-dev"}, OpenShellAdminConfig{RequiredPack: "acme-dev", RequiredPackDigest: "sha256:aa"}},
		{"same required_pack, the same pin", OpenShellAdminConfig{RequiredPack: "/p/pack.yaml", RequiredPackDigest: "sha256:aa"},
			OpenShellAdminConfig{RequiredPack: "/p/pack.yaml", RequiredPackDigest: "sha256:aa"},
			OpenShellAdminConfig{RequiredPack: "/p/pack.yaml", RequiredPackDigest: "sha256:aa"}},
		{"same required_pack pins an unpinned base", OpenShellAdminConfig{RequiredPack: "/p/pack.yaml"},
			OpenShellAdminConfig{RequiredPack: "/p/pack.yaml", RequiredPackDigest: "sha256:bb"},
			OpenShellAdminConfig{RequiredPack: "/p/pack.yaml", RequiredPackDigest: "sha256:bb"}},
		{"required_for union", OpenShellAdminConfig{RequiredFor: []string{"claudecode"}}, OpenShellAdminConfig{RequiredFor: []string{"claude-code", "codex"}},
			OpenShellAdminConfig{RequiredFor: []string{"claudecode", "codex"}}},
		// GAP-0117: F spells connectors canonically, each once.
		{"required_for canonical names", OpenShellAdminConfig{RequiredFor: []string{"Claude_Code"}}, OpenShellAdminConfig{RequiredFor: []string{"claude-code"}},
			OpenShellAdminConfig{RequiredFor: []string{"claudecode"}}},
		{"allowed_harnesses canonical names", OpenShellAdminConfig{AllowedHarnesses: []string{"Claude-Code", "claudecode", "Codex"}},
			OpenShellAdminConfig{}, OpenShellAdminConfig{AllowedHarnesses: []string{"claudecode", "codex"}}},
		{"egress_block union", OpenShellAdminConfig{EgressBlock: []string{"paste.example"}}, OpenShellAdminConfig{EgressBlock: []string{"Paste.Example.", "transfer.sh"}},
			OpenShellAdminConfig{EgressBlock: []string{"paste.example", "transfer.sh"}}},
		{"require_copy_for and locked union", OpenShellAdminConfig{RequireCopyFor: []string{"/src/a"}, Locked: []string{"yolo"}},
			OpenShellAdminConfig{RequireCopyFor: []string{"/src/b"}, Locked: []string{"yolo", "profile"}},
			OpenShellAdminConfig{RequireCopyFor: []string{"/src/a", "/src/b"}, Locked: []string{"yolo", "profile"}}},
		{"allowed_harnesses intersection", OpenShellAdminConfig{AllowedHarnesses: []string{"claudecode", "codex", "opencode"}},
			OpenShellAdminConfig{AllowedHarnesses: []string{"claude-code", "codex"}}, OpenShellAdminConfig{AllowedHarnesses: []string{"claudecode", "codex"}}},
		{"allowed_harnesses unset base", OpenShellAdminConfig{}, OpenShellAdminConfig{AllowedHarnesses: []string{"codex"}}, OpenShellAdminConfig{AllowedHarnesses: []string{"codex"}}},
		{"allowed_credentials intersection", OpenShellAdminConfig{AllowedCredentials: []string{"bedrock", "openai"}},
			OpenShellAdminConfig{AllowedCredentials: []string{"bedrock"}}, OpenShellAdminConfig{AllowedCredentials: []string{"bedrock"}}},
		{"allowed_credentials none absorbs", OpenShellAdminConfig{AllowedCredentials: []string{"bedrock"}},
			OpenShellAdminConfig{AllowedCredentials: []string{"none"}}, OpenShellAdminConfig{AllowedCredentials: []string{"none"}}},
		{"allowed_credentials none base", OpenShellAdminConfig{AllowedCredentials: []string{"none"}},
			OpenShellAdminConfig{AllowedCredentials: []string{"bedrock"}}, OpenShellAdminConfig{AllowedCredentials: []string{"none"}}},
		{"egress_allow_only covers", OpenShellAdminConfig{EgressAllowOnly: []string{"*.corp.example", "github.com"}},
			OpenShellAdminConfig{EgressAllowOnly: []string{"api.corp.example", "pypi.org"}}, OpenShellAdminConfig{EgressAllowOnly: []string{"api.corp.example"}}},
		{"egress_allow_only base inside overlay", OpenShellAdminConfig{EgressAllowOnly: []string{"api.corp.example"}},
			OpenShellAdminConfig{EgressAllowOnly: []string{"*.corp.example"}}, OpenShellAdminConfig{EgressAllowOnly: []string{"api.corp.example"}}},
		{"when_unavailable refuse wins", OpenShellAdminConfig{WhenUnavailable: "alert"}, OpenShellAdminConfig{WhenUnavailable: "refuse"},
			OpenShellAdminConfig{WhenUnavailable: "refuse"}},
		{"when_unavailable unset base (refuse) never loosens", OpenShellAdminConfig{}, OpenShellAdminConfig{WhenUnavailable: "alert"},
			OpenShellAdminConfig{}},
		{"when_unavailable explicit refuse over unset", OpenShellAdminConfig{}, OpenShellAdminConfig{WhenUnavailable: "refuse"},
			OpenShellAdminConfig{}},
		{"when_unavailable alert kept", OpenShellAdminConfig{WhenUnavailable: "alert"}, OpenShellAdminConfig{},
			OpenShellAdminConfig{WhenUnavailable: "alert"}},
		{"foreign_sandboxes stop wins", OpenShellAdminConfig{ForeignSandboxes: "alert"}, OpenShellAdminConfig{ForeignSandboxes: "stop"},
			OpenShellAdminConfig{ForeignSandboxes: "stop"}},
		{"foreign_sandboxes unset base (stop) never loosens", OpenShellAdminConfig{}, OpenShellAdminConfig{ForeignSandboxes: "alert"},
			OpenShellAdminConfig{}},
		{"allow_mount overlay true adds nothing", OpenShellAdminConfig{}, OpenShellAdminConfig{AllowMount: bp(true)}, OpenShellAdminConfig{}},
		{"process_tree overlay false adds nothing", OpenShellAdminConfig{}, OpenShellAdminConfig{ProcessTree: bp(false)}, OpenShellAdminConfig{}},
		{"on_silence stop wins", OpenShellAdminConfig{OnSilence: "alert"}, OpenShellAdminConfig{OnSilence: "stop"}, OpenShellAdminConfig{OnSilence: "stop"}},
		{"on_silence never alert over stop", OpenShellAdminConfig{OnSilence: "stop"}, OpenShellAdminConfig{OnSilence: "alert"}, OpenShellAdminConfig{OnSilence: "stop"}},
		{"on_silence unset base", OpenShellAdminConfig{}, OpenShellAdminConfig{OnSilence: "alert"}, OpenShellAdminConfig{OnSilence: "alert"}},
		{"user_approvals none over session", OpenShellAdminConfig{UserApprovals: "session"}, OpenShellAdminConfig{UserApprovals: "none"},
			OpenShellAdminConfig{UserApprovals: "none"}},
		{"user_approvals session over unset", OpenShellAdminConfig{}, OpenShellAdminConfig{UserApprovals: "session"}, OpenShellAdminConfig{UserApprovals: "session"}},
		{"user_approvals never looser", OpenShellAdminConfig{UserApprovals: "none"}, OpenShellAdminConfig{UserApprovals: "session"},
			OpenShellAdminConfig{UserApprovals: "none"}},
		{"max_silence_after minimum", OpenShellAdminConfig{MaxSilenceAfter: "10m"}, OpenShellAdminConfig{MaxSilenceAfter: "300s"},
			OpenShellAdminConfig{MaxSilenceAfter: "300s"}},
		{"max_silence_after clamped to a minute", OpenShellAdminConfig{MaxSilenceAfter: "10m"}, OpenShellAdminConfig{MaxSilenceAfter: "30s"},
			OpenShellAdminConfig{MaxSilenceAfter: "1m0s"}},
		{"delete_stopped_after minimum in days", OpenShellAdminConfig{DeleteStoppedAfter: "14d"}, OpenShellAdminConfig{DeleteStoppedAfter: "48h"},
			OpenShellAdminConfig{DeleteStoppedAfter: "48h"}},
		{"delete_stopped_after never longer", OpenShellAdminConfig{DeleteStoppedAfter: "24h"}, OpenShellAdminConfig{DeleteStoppedAfter: "2d"},
			OpenShellAdminConfig{DeleteStoppedAfter: "24h"}},
		{"max_resources minimum", OpenShellAdminConfig{MaxResources: OpenShellResourcesConfig{CPU: "2", Memory: "8Gi"}},
			OpenShellAdminConfig{MaxResources: OpenShellResourcesConfig{CPU: "500m", Memory: "16Gi"}},
			OpenShellAdminConfig{MaxResources: OpenShellResourcesConfig{CPU: "500m", Memory: "8Gi"}}},
		{"request_access profile overrides", OpenShellAdminConfig{RequestAccess: "it@example.com"}, OpenShellAdminConfig{RequestAccess: "contractor-desk@example.com"},
			OpenShellAdminConfig{RequestAccess: "contractor-desk@example.com"}},
		{"request_access base kept", OpenShellAdminConfig{RequestAccess: "it@example.com"}, OpenShellAdminConfig{}, OpenShellAdminConfig{RequestAccess: "it@example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			overlay := tc.overlay
			got, err := TightenOpenShellAdmin(tc.base, &overlay)
			if err != nil {
				t.Fatalf("TightenOpenShellAdmin: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
			// Tightening never loosens: applying the overlay again changes nothing.
			again, err := TightenOpenShellAdmin(got, &overlay)
			if err != nil || !reflect.DeepEqual(again, got) {
				t.Fatalf("not idempotent: %+v, %v", again, err)
			}
		})
	}
}

// A nil overlay adds nothing and the result never aliases the inputs.
func TestTightenOpenShellAdminNilOverlayAndNoAliasing(t *testing.T) {
	base := OpenShellAdminConfig{AllowMount: bp(true), RequiredFor: []string{"codex"}, EgressBlock: []string{"paste.example"}}
	got, err := TightenOpenShellAdmin(base, nil)
	if err != nil || !reflect.DeepEqual(got, base) {
		t.Fatalf("nil overlay: %+v, %v", got, err)
	}
	*got.AllowMount = false
	got.RequiredFor[0] = "claudecode"
	if !*base.AllowMount || base.RequiredFor[0] != "codex" {
		t.Fatal("the result aliases the base")
	}
	empty, err := TightenOpenShellAdmin(OpenShellAdminConfig{}, &OpenShellAdminConfig{})
	if err != nil || !empty.IsZero() {
		t.Fatalf("empty overlay over an empty base: %+v, %v", empty, err)
	}
	// GAP-0117: the nil-overlay floor is canonical too (what the L5 gate and
	// the resolver compare exactly).
	spelled := OpenShellAdminConfig{RequiredFor: []string{"claude-code", "Claude_Code"}, AllowedHarnesses: []string{"Claude-Code", "codex"}}
	got, err = TightenOpenShellAdmin(spelled, nil)
	if err != nil || !reflect.DeepEqual(got.RequiredFor, []string{"claudecode"}) || !reflect.DeepEqual(got.AllowedHarnesses, []string{"claudecode", "codex"}) {
		t.Fatalf("nil overlay keeps the spelling: %+v, %v", got, err)
	}
	if spelled.RequiredFor[0] != "claude-code" {
		t.Fatal("canonicalizing rewrote the base")
	}
}

func TestTightenOpenShellAdminContradictions(t *testing.T) {
	cases := []struct {
		name          string
		base, overlay OpenShellAdminConfig
		field, want   string
	}{
		{"allowed false from the base with required_for", OpenShellAdminConfig{Allowed: bp(false)}, OpenShellAdminConfig{RequiredFor: []string{"codex"}},
			"allowed", "sandbox: combined with openshell.admin, allowed: false contradicts required_for [codex]: a required agent could not run anywhere"},
		{"required_for from the base with allowed false", OpenShellAdminConfig{RequiredFor: []string{"claudecode"}}, OpenShellAdminConfig{Allowed: bp(false)},
			"allowed", "allowed: false contradicts required_for [claudecode]"},
		{"harnesses", OpenShellAdminConfig{AllowedHarnesses: []string{"claudecode", "codex"}}, OpenShellAdminConfig{AllowedHarnesses: []string{"opencode"}},
			"allowed_harnesses", "sandbox: combined with openshell.admin, allowed_harnesses [opencode] leaves no harness (openshell.admin allows [claudecode, codex])"},
		{"credentials", OpenShellAdminConfig{AllowedCredentials: []string{"openai"}}, OpenShellAdminConfig{AllowedCredentials: []string{"bedrock"}},
			"allowed_credentials", "allowed_credentials [bedrock] leaves no credential (openshell.admin allows [openai])"},
		{"egress", OpenShellAdminConfig{EgressAllowOnly: []string{"*.corp.example"}}, OpenShellAdminConfig{EgressAllowOnly: []string{"github.com"}},
			"egress_allow_only", "egress_allow_only [github.com] leaves no destination (openshell.admin allows [*.corp.example])"},
		{"two pins for one pack", OpenShellAdminConfig{RequiredPack: "/p/pack.yaml", RequiredPackDigest: "sha256:aa"},
			OpenShellAdminConfig{RequiredPack: "/p", RequiredPackDigest: "sha256:bb"}, "required_pack_digest",
			`sandbox: combined with openshell.admin, required_pack_digest sha256:bb contradicts sha256:aa for the same pack "/p": no pack content matches both`},
		{"required agent outside the profile's harnesses", OpenShellAdminConfig{RequiredFor: []string{"claude-code"}},
			OpenShellAdminConfig{AllowedHarnesses: []string{"codex"}}, "required_for",
			"sandbox: combined with openshell.admin, required_for [claudecode] is outside allowed_harnesses [codex]: a required agent could not run anywhere"},
		{"profile requires an agent the base's harnesses leave out", OpenShellAdminConfig{AllowedHarnesses: []string{"codex", "opencode"}},
			OpenShellAdminConfig{RequiredFor: []string{"codex", "claudecode"}}, "required_for",
			"required_for [claudecode] is outside allowed_harnesses [codex, opencode]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			overlay := tc.overlay
			_, err := TightenOpenShellAdmin(tc.base, &overlay)
			var contradiction *SandboxPolicyContradictionError
			if !errors.As(err, &contradiction) {
				t.Fatalf("err = %v, want a contradiction", err)
			}
			if contradiction.Field != tc.field || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("contradiction = %q on %s, want %q on %s", err, contradiction.Field, tc.want, tc.field)
			}
		})
	}
}

func sandboxProfilesFixture() *Config {
	cfg := &Config{}
	cfg.OpenShell.Admin = OpenShellAdminConfig{
		EgressBlock: []string{"pastebin.com"}, ForeignSandboxes: "stop", RequestAccess: "it-security@example.com",
	}
	cfg.Guardrail.Profiles = map[string]GuardrailProfile{
		"contractors": {Mode: "action", Sandbox: &OpenShellAdminConfig{
			RequiredFor: []string{"claudecode", "codex"}, AllowedHarnesses: []string{"claudecode", "codex"},
			EgressAllowOnly: []string{"api.anthropic.com", "github.com"}, AllowMount: bp(false), AllowUnblock: bp(false),
			UserApprovals: "session", AllowedCredentials: []string{"bedrock"}, ProcessTree: bp(true), DeleteStoppedAfter: "14d",
			WhenUnavailable: "refuse", ForeignSandboxes: "stop", AllowYolo: bp(true),
		}},
		"engineering":    {Sandbox: &OpenShellAdminConfig{AllowedHarnesses: []string{"claudecode", "codex", "opencode", "hermes"}, OnSilence: "stop", MaxSilenceAfter: "5m"}},
		"offline-floor":  {Sandbox: &OpenShellAdminConfig{RequiredFor: []string{"claudecode"}, MinProfile: "strict", AllowMount: bp(false)}},
		"guardrail-only": {Mode: "observe"},
	}
	cfg.Guardrail.ProfileAssignments = []ProfileAssignment{
		{Profile: "contractors", Match: ProfileMatch{Groups: []string{`CORP\Contractors`}}},
		{Profile: "engineering", Match: ProfileMatch{Groups: []string{`CORP\Engineering`}}},
		{Profile: "guardrail-only", Match: ProfileMatch{Connectors: []string{"cursor"}}},
	}
	cfg.Guardrail.DefaultProfile = "offline-floor"
	return cfg
}

func TestValidateSandboxProfiles(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "valid", mutate: func(*Config) {}},
		{name: "contradiction", mutate: func(c *Config) { c.OpenShell.Admin.Allowed = bp(false) },
			want: `guardrail.profiles["contractors"]: sandbox: combined with openshell.admin, allowed: false contradicts required_for`},
		{name: "unknown connector", mutate: func(c *Config) { c.Guardrail.Profiles["offline-floor"].Sandbox.RequiredFor = []string{"notepad"} },
			want: `guardrail.profiles["offline-floor"]: sandbox.required_for[0]: "notepad" is not a known connector`},
		{name: "none mixed", mutate: func(c *Config) {
			c.Guardrail.Profiles["contractors"].Sandbox.AllowedCredentials = []string{"none", "bedrock"}
		}, want: "sandbox.allowed_credentials: none cannot be combined with other credentials"},
		{name: "explicit empty list", mutate: func(c *Config) { c.Guardrail.Profiles["engineering"].Sandbox.AllowedHarnesses = []string{} },
			want: "sandbox.allowed_harnesses: an empty list is refused; leave the key out for no constraint"},
		{name: "short silence", mutate: func(c *Config) { c.Guardrail.Profiles["engineering"].Sandbox.MaxSilenceAfter = "30s" },
			want: `sandbox.max_silence_after "30s" must be at least 1m`},
		{name: "short retention", mutate: func(c *Config) { c.Guardrail.Profiles["contractors"].Sandbox.DeleteStoppedAfter = "30m" },
			want: `sandbox.delete_stopped_after "30m" must be at least 1h`},
		{name: "long request_access", mutate: func(c *Config) {
			c.Guardrail.Profiles["contractors"].Sandbox.RequestAccess = strings.Repeat("x", 513)
		}, want: "sandbox.request_access must be at most 512 bytes"},
		{name: "control character in request_access", mutate: func(c *Config) {
			c.Guardrail.Profiles["contractors"].Sandbox.RequestAccess = "call\nme"
		}, want: "sandbox.request_access must be printable text on one line"},
		{name: "required agent outside its own harnesses", mutate: func(c *Config) {
			c.Guardrail.Profiles["contractors"].Sandbox.AllowedHarnesses = []string{"codex"}
		}, want: `guardrail.profiles["contractors"]: sandbox: required_for [claudecode] is outside allowed_harnesses [codex]: a required agent could not run anywhere`},
		{name: "required agent outside the base harnesses", mutate: func(c *Config) { c.OpenShell.Admin.AllowedHarnesses = []string{"codex", "opencode"} },
			want: `guardrail.profiles["contractors"]: sandbox: combined with openshell.admin, required_for [claudecode] is outside allowed_harnesses [codex]`},
		{name: "same pack, two pins", mutate: func(c *Config) {
			c.OpenShell.Admin.RequiredPack, c.OpenShell.Admin.RequiredPackDigest = "/srv/packs/acme", "sha256:"+strings.Repeat("a", 64)
			s := c.Guardrail.Profiles["contractors"].Sandbox
			s.RequiredPack, s.RequiredPackDigest = "/srv/packs/acme/pack.yaml", "sha256:"+strings.Repeat("b", 64)
		}, want: `sandbox: combined with openshell.admin, required_pack_digest sha256:bbbb`},
		{name: "secure client refuses the profiles", mutate: func(c *Config) {
			c.DeploymentMode, c.Enterprise.Profile = "managed_enterprise", "secure_client"
		}, want: "not supported with the Secure Client integration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sandboxProfilesFixture()
			tc.mutate(cfg)
			err := cfg.ValidateGuardrailProfiles()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateGuardrailProfiles() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateGuardrailProfiles() = %v, want %q", err, tc.want)
			}
		})
	}
}

// The profile pack strictness hook runs for every profile floor with a pack
// or a pin of its own, with or without a base pack (GAP-0268, GAP-0380), and
// its refusal is the load error, so ensure keeps the previous config.
func TestSandboxProfilePackCheckHook(t *testing.T) {
	pin := "sha256:" + strings.Repeat("0", 64)
	for _, tc := range []struct {
		name               string
		base, pack, digest string
		want               string
	}{
		{name: "both set", base: "balanced", pack: "open", want: "balanced>open>"},
		{name: "no base pack", pack: "/srv/packs/loose", want: ">/srv/packs/loose>"},
		{name: "profile pin", pack: "/srv/packs/acme", digest: pin, want: ">/srv/packs/acme>" + pin},
		{name: "own pin on the base pack", base: "/srv/packs/acme", pack: "/srv/packs/acme/pack.yaml", digest: pin, want: "/srv/packs/acme>/srv/packs/acme>" + pin},
		{name: "the base pack itself", base: "balanced", pack: "balanced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sandboxProfilesFixture()
			cfg.OpenShell.Admin.RequiredPack = tc.base
			s := cfg.Guardrail.Profiles["contractors"].Sandbox
			s.RequiredPack, s.RequiredPackDigest = tc.pack, tc.digest
			var calls []string
			old := SandboxProfilePackCheck
			t.Cleanup(func() { SandboxProfilePackCheck = old })
			SandboxProfilePackCheck = func(_ *Config, base, profile, digest string) error {
				calls = append(calls, base+">"+profile+">"+digest)
				return errors.New("pack is looser than balanced in network.mode")
			}
			err := cfg.ValidateGuardrailProfiles()
			if tc.want == "" {
				if err != nil || len(calls) != 0 {
					t.Fatalf("err = %v, calls = %v", err, calls)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), `guardrail.profiles["contractors"]: sandbox.required_pack: pack is looser`) {
				t.Fatalf("err = %v", err)
			}
			if strings.Join(calls, ",") != tc.want {
				t.Fatalf("calls = %v, want %s", calls, tc.want)
			}
		})
	}
}

// On a managed standalone host a profile or base pack must live in
// <policy_dir>/sandbox/: a path where it really is, a custom name where
// openshell.pack_dir puts it; "~" paths and links out are refused. A
// built-in pack name is not a file.
func TestManagedSandboxPackLocation(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "sandbox")
	inside := filepath.Join(root, "contractors", "pack.yaml")
	outside := filepath.Join(dir, "other")
	for _, d := range []string{filepath.Dir(inside), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{inside, filepath.Join(outside, "pack.yaml")} {
		if err := os.WriteFile(f, []byte("name: contractors\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"escape": outside, "dangling": filepath.Join(dir, "later"), "alias": filepath.Dir(inside),
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Skipf("symbolic links: %v", err)
		}
	}
	cfg := &Config{PolicyDir: dir, DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	for _, tc := range []struct {
		pack, packDir string
		ok            bool
	}{
		{"strict", "", true}, {inside, "", true}, {filepath.Join(root, "contractors"), "", true},
		{filepath.Join(root, "new", "pack.yaml"), "", true},
		{filepath.Join(root, "..", "pack.yaml"), "", false},
		{filepath.Join(outside, "pack.yaml"), "", false}, {root, "", false},
		{"~/packs/contractors/pack.yaml", "", false}, {"~", "", false}, {"packs/contractors", "", false},
		{filepath.Join(root, "escape", "pack.yaml"), "", false},
		{filepath.Join(root, "dangling", "pack.yaml"), "", false},
		{filepath.Join(root, "alias", "pack.yaml"), "", true},
		{"contractors", root, true}, {"contractors", outside, false}, {"contractors", "", false},
		{"contractors", "~/sandbox", false}, {"escape", root, false},
	} {
		cfg.OpenShell.PackDir = tc.packDir
		err := cfg.validateManagedSandboxPack("admin", tc.pack)
		if (err == nil) != tc.ok {
			t.Errorf("%s (pack_dir %q): err = %v, want ok=%t", tc.pack, tc.packDir, err, tc.ok)
		}
	}
	cfg.OpenShell.PackDir = outside
	if err := cfg.validateManagedSandboxPack(`guardrail.profiles["contractors"].sandbox`, "contractors"); err == nil ||
		!strings.Contains(err.Error(), `guardrail.profiles["contractors"].sandbox.required_pack "contractors" names a custom pack, which must be inside `+root) {
		t.Fatalf("custom name outside: %v", err)
	}
	cfg.DeploymentMode = ""
	if err := cfg.validateManagedSandboxPack("admin", filepath.Join(dir, "other", "pack.yaml")); err != nil {
		t.Fatalf("unmanaged hosts keep any pack path: %v", err)
	}
}

// Secure Client stays byte-identical: every managed floor key under
// openshell.admin is refused with the pinned text, and a config without
// them still loads.
func TestSecureClientRefusesManagedFloorKeysGolden(t *testing.T) {
	sc := func(admin OpenShellAdminConfig) *Config {
		cfg := &Config{DeploymentMode: "managed_enterprise"}
		cfg.Enterprise.Profile = "secure_client"
		cfg.OpenShell.Admin = admin
		return cfg
	}
	if err := sc(OpenShellAdminConfig{EgressBlock: []string{"paste.example"}, AllowMount: bp(false)}).ValidateOpenShell(); err != nil {
		t.Fatalf("pre-existing admin keys under Secure Client: %v", err)
	}
	var got []string
	keys := []OpenShellAdminConfig{
		{Allowed: bp(true)}, {RequiredFor: []string{"codex"}}, {WhenUnavailable: "alert"}, {UserApprovals: "none"},
		{AllowedCredentials: []string{"bedrock"}}, {OnSilence: "stop"}, {MaxSilenceAfter: "5m"}, {ProcessTree: bp(true)},
		{ForeignSandboxes: "alert"}, {AllowUpstreamTelemetry: bp(false)}, {DeleteStoppedAfter: "14d"}, {RequestAccess: "it@example.com"},
		{DriverFallback: "none"},
		{Allowed: bp(true), RequestAccess: "it@example.com"},
	}
	for _, admin := range keys {
		err := sc(admin).ValidateOpenShell()
		if err == nil {
			t.Fatalf("%+v accepted under Secure Client", admin)
		}
		got = append(got, err.Error())
	}
	golden := filepath.Join("testdata", "sandbox_secure_client_refusals.golden")
	text := strings.Join(got, "\n") + "\n"
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != text {
		t.Fatalf("Secure Client refusals changed:\n%s\nwant:\n%s", text, want)
	}
	// A profile sandbox section is refused with every other profile key.
	cfg := sc(OpenShellAdminConfig{})
	cfg.Guardrail.Profiles = map[string]GuardrailProfile{"p": {Sandbox: &OpenShellAdminConfig{ProcessTree: bp(true)}}}
	if err := cfg.ValidateGuardrailProfiles(); err == nil || !strings.Contains(err.Error(), "not supported with the Secure Client integration") {
		t.Fatalf("profile sandbox under Secure Client: %v", err)
	}
}

// Profiles without a sandbox section keep their digests (pinned from before
// the sandbox section existed), with or without an openshell.admin floor; a
// profile with one digests it.
func TestGuardrailProfileDigestStableWithoutSandbox(t *testing.T) {
	const pinned = "sha256:7298830b7990cee230c2af75a8a6f009d79ef61296448a1ba8f817de3966755e"
	base := profileDerivationFixture()
	derived, err := base.DeriveGuardrailProfiles()
	if err != nil {
		t.Fatal(err)
	}
	plain := derived["watch"].Digest
	if plain != pinned {
		t.Fatalf("digest of a profile without a sandbox section = %s, want the pre-sandbox %s", plain, pinned)
	}
	base.OpenShell.Admin = OpenShellAdminConfig{EgressBlock: []string{"paste.example"}}
	if derived, err = base.DeriveGuardrailProfiles(); err != nil || derived["watch"].Digest != pinned {
		t.Fatalf("openshell.admin moved a profile digest: %v, %v", derived["watch"].Digest, err)
	}
	if derived["watch"].SandboxDigest == "" || !reflect.DeepEqual(derived["watch"].Sandbox, base.OpenShell.Admin) {
		t.Fatalf("watch floor = %+v %s, want openshell.admin", derived["watch"].Sandbox, derived["watch"].SandboxDigest)
	}
	p := base.Guardrail.Profiles["watch"]
	p.Sandbox = &OpenShellAdminConfig{AllowMount: bp(false)}
	base.Guardrail.Profiles["watch"] = p
	derived, err = base.DeriveGuardrailProfiles()
	if err != nil || derived["watch"].Digest == pinned {
		t.Fatalf("a sandbox section left the profile digest unchanged: %v", err)
	}
	if f := derived["watch"].Sandbox; f.AllowMount == nil || *f.AllowMount || len(f.EgressBlock) != 1 {
		t.Fatalf("watch floor = %+v", f)
	}
}

// The floor digest ignores list order, and covers the pack file's content.
func TestSandboxFloorDigest(t *testing.T) {
	a, _ := sandboxFloorDigest(OpenShellAdminConfig{EgressBlock: []string{"a.example", "b.example"}, RequiredFor: []string{"codex", "claudecode"}}, "")
	b, _ := sandboxFloorDigest(OpenShellAdminConfig{EgressBlock: []string{"b.example", "a.example"}, RequiredFor: []string{"claudecode", "codex"}}, "")
	if a != b || !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("order-sensitive digest: %s vs %s", a, b)
	}
	packDir := t.TempDir()
	pack := filepath.Join(packDir, "contractors", "pack.yaml")
	if err := os.MkdirAll(filepath.Dir(pack), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pack, []byte("name: contractors\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digests := func() []string {
		var out []string
		for _, ref := range []string{pack, filepath.Dir(pack), "contractors"} {
			d, err := sandboxFloorDigest(OpenShellAdminConfig{RequiredPack: ref}, packDir)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, d)
		}
		return out
	}
	before := digests()
	if err := os.WriteFile(pack, []byte("name: contractors\nnetwork: {mode: open}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after := digests()
	for i := range before {
		if before[i] == after[i] {
			t.Fatalf("reference %d: the floor digest does not cover the pack content", i)
		}
	}
	// GAP-0116: a custom name resolves through pack_dir; a missing,
	// oversized or built-in pack is named for what it is, never truncated.
	if got := sandboxPackContentDigest("contractors", packDir); got != sandboxPackContentDigest(pack, "") || !strings.HasPrefix(got, "file:sha256:") {
		t.Fatalf("custom name digest = %s", got)
	}
	if got := sandboxPackContentDigest(filepath.Join(packDir, "gone", "pack.yaml"), ""); got != "missing" {
		t.Fatalf("missing pack = %s", got)
	}
	if got := sandboxPackContentDigest("contractors", ""); got != "contractors" {
		t.Fatalf("unresolvable name = %s", got)
	}
	big := filepath.Join(packDir, "big.yaml")
	if err := os.WriteFile(big, make([]byte, maxSandboxPackDigestBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sandboxPackContentDigest(big, ""); got != "oversized" {
		t.Fatalf("oversized pack = %s", got)
	}
	if got := sandboxPackContentDigest("strict", packDir); !strings.HasPrefix(got, "builtin:strict:sha256:") {
		t.Fatalf("built-in pack = %s", got)
	}
	cfg := sandboxProfilesFixture()
	f, digest, err := cfg.SandboxFloor("contractors")
	if err != nil || digest == "" {
		t.Fatalf("SandboxFloor: %v", err)
	}
	if f.RequestAccess != "it-security@example.com" || f.ForeignSandboxes != "stop" || len(f.RequiredFor) != 2 {
		t.Fatalf("contractors floor = %+v", f)
	}
	if _, _, err := cfg.SandboxFloor("missing"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	if admin, _, err := cfg.SandboxFloor(""); err != nil || !reflect.DeepEqual(admin, cfg.OpenShell.Admin) {
		t.Fatalf("empty profile = %+v, %v", admin, err)
	}
}

func TestSandboxDefaultProfileWarnings(t *testing.T) {
	got := sandboxProfilesFixture().SandboxDefaultProfileWarnings()
	for _, want := range []string{
		"default_profile lacks required_for [codex] from contractors",
		"default_profile lacks allowed_harnesses [claudecode, codex] from contractors",
		"default_profile lacks allow_unblock false from contractors",
		"default_profile lacks user_approvals session from contractors",
		"default_profile lacks on_silence stop from engineering",
	} {
		found := false
		for _, w := range got {
			found = found || w == want
		}
		if !found {
			t.Errorf("missing warning %q in %q", want, got)
		}
	}
	for _, w := range got {
		if strings.Contains(w, "request_access") || strings.Contains(w, "guardrail-only") || strings.Contains(w, "allow_mount") ||
			strings.Contains(w, "when_unavailable") || strings.Contains(w, "foreign_sandboxes") || strings.Contains(w, "allow_yolo") {
			t.Errorf("unexpected warning %q", w)
		}
	}
	if w := (&Config{}).SandboxDefaultProfileWarnings(); w != nil {
		t.Fatalf("no sandbox policy, warnings %q", w)
	}
}

// GAP-0118(b): a default pack the strictness hook judges no looser than an
// assigned profile's pack is not reported; a looser one, or one no hook can
// judge, is.
func TestSandboxDefaultProfileWarningsPackStrictness(t *testing.T) {
	cfg := sandboxProfilesFixture()
	cfg.Guardrail.Profiles["offline-floor"].Sandbox.RequiredPack = "strict"
	cfg.Guardrail.Profiles["engineering"].Sandbox.RequiredPack = "balanced"
	packWarning := func() bool {
		for _, w := range cfg.SandboxDefaultProfileWarnings() {
			if strings.HasPrefix(w, "default_profile lacks required_pack") {
				return true
			}
		}
		return false
	}
	old := SandboxProfilePackCheck
	t.Cleanup(func() { SandboxProfilePackCheck = old })
	SandboxProfilePackCheck = nil
	if !packWarning() {
		t.Fatal("without the strictness hook a differing pack is reported")
	}
	rank := map[string]int{"open": 0, "balanced": 1, "strict": 2}
	SandboxProfilePackCheck = func(_ *Config, base, profile, _ string) error {
		if rank[profile] < rank[base] {
			return errors.New("looser")
		}
		return nil
	}
	if packWarning() {
		t.Fatalf("a stricter default pack is reported: %q", cfg.SandboxDefaultProfileWarnings())
	}
	cfg.Guardrail.Profiles["offline-floor"].Sandbox.RequiredPack = "open"
	if !packWarning() {
		t.Fatal("a looser default pack is not reported")
	}
}

// GAP-0535: a required_for connector whose hooks the standalone profile
// does not publish through machine policy (Antigravity's are per user), or
// whose machine policy the administrator turned off, is named; OpenCode's
// managed plugin is named as a condition.
func TestSandboxAdvisoriesNameConnectorsWithoutMachineHooks(t *testing.T) {
	old := SandboxMachinePolicyRoute
	t.Cleanup(func() { SandboxMachinePolicyRoute = old })
	SandboxMachinePolicyRoute = func(connector, _ string) bool { return connector == "claudecode" || connector == "codex" }
	cfg := sandboxProfilesFixture()
	cfg.Guardrail.Profiles["offline-floor"].Sandbox.RequiredFor = []string{"claudecode", "antigravity", "opencode"}
	got := strings.Join(cfg.SandboxAdvisories("linux"), "\n")
	for _, want := range []string{
		"required_for names antigravity (offline-floor), which has no machine-owned hook on linux",
		"required_for names opencode (offline-floor), whose hook on linux is machine-owned only while OpenCode's managed config loads the DefenseClaw plugin",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing advisory %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "names claudecode") || strings.Contains(got, "names codex") {
		t.Errorf("a machine-owned hook is named:\n%s", got)
	}
	cfg.Enterprise.MachinePolicy.Connectors = map[string]EnterpriseConnectorPolicy{"codex": {Ownership: MachinePolicyOwnershipOff}}
	if got := strings.Join(cfg.SandboxAdvisories("linux"), "\n"); !strings.Contains(got, "required_for names codex (contractors), which has no machine-owned hook on linux") {
		t.Errorf("codex with machine policy off is not named:\n%s", got)
	}
}

func TestEnterpriseOpenShellValidation(t *testing.T) {
	cases := []struct {
		name, goos string
		o          EnterpriseOpenShellConfig
		want       string
	}{
		{"defaults", "linux", EnterpriseOpenShellConfig{}, ""},
		{"setup exact", "darwin", EnterpriseOpenShellConfig{Install: "setup", Driver: "vm", Version: "0.1.3", GatewayPort: 17671, E2fsprogsDir: "/opt/cisco/defenseclaw-deps/e2fsprogs"}, ""},
		{"setup missing pin with sandboxes off", "darwin", EnterpriseOpenShellConfig{Install: "setup", Driver: "vm"}, ""},
		{"prerequisite range", "linux", EnterpriseOpenShellConfig{Install: "prerequisite", Version: ">=0.1.1 <0.2.0"}, ""},
		{"linux vm prerequisite is judged by ensure", "linux", EnterpriseOpenShellConfig{Driver: "vm"}, ""},
		{"setup range", "linux", EnterpriseOpenShellConfig{Install: "setup", Version: ">=0.1.1"}, "install: setup needs an exact version"},
		{"empty range", "linux", EnterpriseOpenShellConfig{Version: ">=0.2.0 <0.1.0"}, "is an empty range"},
		{"bad version", "linux", EnterpriseOpenShellConfig{Version: "latest"}, "must be an exact version"},
		{"bad install", "linux", EnterpriseOpenShellConfig{Install: "bundled"}, "enterprise.openshell.install"},
		{"e2fsprogs on linux", "linux", EnterpriseOpenShellConfig{E2fsprogsDir: "/opt/e2fsprogs"}, "applies to macOS only"},
		{"relative e2fsprogs", "darwin", EnterpriseOpenShellConfig{E2fsprogsDir: "opt/e2fsprogs"}, "must be a clean absolute path"},
		{"low port", "linux", EnterpriseOpenShellConfig{GatewayPort: 80}, "between 1024 and 65535"},
		{"api port", "linux", EnterpriseOpenShellConfig{GatewayPort: 18970}, "collides with gateway.api_port"},
		{"ingress port", "linux", EnterpriseOpenShellConfig{GatewayPort: 18971}, "collides with openshell.ingress_port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Enterprise.OpenShell = tc.o
			err := validateEnterpriseOpenShell(cfg, tc.goos)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A 1.0.2/1.0.3 standalone config could retain install: setup without a pin
// while sandboxes were off. Loading it must survive 1.0.4; an enabled setup
// still needs an installable pin when the lifecycle plans the change.
func TestEnterpriseOpenShellUnpinnedSetupOffUpgradeConfig(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			cfg := &Config{DeploymentMode: "managed_enterprise"}
			cfg.Enterprise.Profile = "standalone"
			cfg.Enterprise.OpenShell = EnterpriseOpenShellConfig{Install: "setup", Driver: "docker"}
			if err := resolveEnterpriseConfig(cfg, goos, "standalone"); err != nil {
				t.Fatalf("off config refused after upgrade: %v", err)
			}
			cfg.OpenShell.Enabled = true
			if err := resolveEnterpriseConfig(cfg, goos, "standalone"); err != nil {
				t.Fatalf("enabled unpinned setup config refused on load: %v", err)
			}
		})
	}
}

// GAP-0118(c, d): a standalone host checks the default gateway port too,
// and a loader without the schema keeps install and driver lowercase.
func TestEnterpriseOpenShellStandaloneDefaults(t *testing.T) {
	standalone := func(o EnterpriseOpenShellConfig, apiPort int) *Config {
		cfg := &Config{DeploymentMode: "managed_enterprise"}
		cfg.Enterprise.Profile = "standalone"
		cfg.Enterprise.OpenShell = o
		cfg.Gateway.APIPort = apiPort
		return cfg
	}
	cfg := standalone(EnterpriseOpenShellConfig{}, DefaultEnterpriseOpenShellGatewayPort)
	if err := resolveEnterpriseConfig(cfg, "linux", "standalone"); err == nil ||
		!strings.Contains(err.Error(), "gateway_port 17670 collides with gateway.api_port (the default; set enterprise.openshell.gateway_port)") {
		t.Fatalf("default port collision: %v", err)
	}
	// GAP-0553: the refusal names the setting, so `config validate` shows it
	// instead of "configuration could not be compiled safely" at "$".
	var setting *SettingError
	if err := resolveEnterpriseConfig(standalone(EnterpriseOpenShellConfig{}, DefaultEnterpriseOpenShellGatewayPort), "linux", "standalone"); !errors.As(err, &setting) ||
		setting.Path != "enterprise.openshell.gateway_port" || !strings.Contains(setting.Detail(), "collides with gateway.api_port") {
		t.Fatalf("default port collision is not a setting error at enterprise.openshell.gateway_port: %#v", err)
	}
	if err := resolveEnterpriseConfig(standalone(EnterpriseOpenShellConfig{Install: "bundled"}, 0), "linux", "standalone"); !errors.As(err, &setting) ||
		setting.Path != "enterprise.openshell.install" {
		t.Fatalf("a bad install value is not a setting error at enterprise.openshell.install: %#v", err)
	}
	if err := resolveEnterpriseConfig(standalone(EnterpriseOpenShellConfig{GatewayPort: 17680}, DefaultEnterpriseOpenShellGatewayPort), "linux", "standalone"); err != nil {
		t.Fatalf("a moved gateway port: %v", err)
	}
	cfg = standalone(EnterpriseOpenShellConfig{Install: " SETUP", Driver: "VM ", Version: "0.1.3"}, 0)
	if err := resolveEnterpriseConfig(cfg, "linux", "standalone"); err != nil {
		t.Fatal(err)
	}
	if o := cfg.Enterprise.OpenShell; o.Install != "setup" || o.Driver != "vm" {
		t.Fatalf("install %q driver %q, want lowercase", o.Install, o.Driver)
	}
	cfg = standalone(EnterpriseOpenShellConfig{Install: "Setup", Version: ">=0.1.1"}, 0)
	if err := resolveEnterpriseConfig(cfg, "linux", "standalone"); err == nil || !strings.Contains(err.Error(), "install: setup needs an exact version") {
		t.Fatalf("a folded setup with a range: %v", err)
	}
}

func TestParseOpenShellFloorDuration(t *testing.T) {
	for in, want := range map[string]string{"14d": "336h0m0s", "90s": "1m30s", "1h": "1h0m0s"} {
		d, err := ParseOpenShellFloorDuration(in)
		if err != nil || d.String() != want {
			t.Errorf("%s = %v, %v", in, d, err)
		}
	}
	for _, bad := range []string{"", "2w", "-1h", "+1h", "1.5d", "5"} {
		if _, err := ParseOpenShellFloorDuration(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSandboxAdvisories(t *testing.T) {
	cfg := sandboxProfilesFixture()
	cfg.Guardrail.Profiles["offline-floor"].Sandbox.RequiredFor = []string{"claudecode", "example-plugin"}
	cfg.Guardrail.ProfileAssignments = append(cfg.Guardrail.ProfileAssignments,
		ProfileAssignment{Profile: "engineering", Match: ProfileMatch{Agents: []string{"agt-0123456789abcdef"}}})
	cfg.OpenShell.Admin.RequestAccess = ""
	// GAP-0393: a custom pack without a pin is named; a built-in or a pinned
	// one is not.
	cfg.Guardrail.Profiles["contractors"].Sandbox.RequiredPack = "/srv/packs/contractors/pack.yaml"
	cfg.Guardrail.Profiles["engineering"].Sandbox.RequiredPack = "/srv/packs/engineering"
	cfg.Guardrail.Profiles["engineering"].Sandbox.RequiredPackDigest = "sha256:" + strings.Repeat("a", 64)
	cfg.Guardrail.Profiles["offline-floor"].Sandbox.RequiredPack = "strict"
	got := strings.Join(cfg.SandboxAdvisories("windows"), "\n")
	for _, want := range []string{
		"required_for names example-plugin (offline-floor), which has no machine-owned hook on windows",
		"guardrail.profile_assignments[3] reaches the sandbox floor of engineering only through match.agents or match.connectors",
		`openshell.admin.request_access is empty: sandbox refusals end with "contact your IT help desk"`,
		`guardrail.profiles["contractors"].sandbox.required_pack /srv/packs/contractors/pack.yaml has no required_pack_digest`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing advisory %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "claudecode (") || strings.Contains(got, "assignments[2]") ||
		strings.Contains(got, "/srv/packs/engineering") || strings.Contains(got, "required_pack strict") {
		t.Errorf("unexpected advisory in:\n%s", got)
	}
	if again := strings.Join(cfg.SandboxAdvisories("windows"), "\n"); again != got {
		t.Errorf("advisories differ on a rerun:\n%s\n---\n%s", got, again)
	}
	linux := strings.Join(cfg.SandboxAdvisories("linux"), "\n")
	if strings.Contains(linux, "example-plugin") {
		t.Errorf("a plugin connector has hooks on linux:\n%s", linux)
	}
	// GAP-0484: the pin advice names the reader root can run on a managed
	// computer, not `defenseclaw sandbox pack show` (which needs a daemon).
	for goos, want := range map[string]string{
		"linux":   "`/opt/defenseclaw/bin/defenseclaw-gateway enterprise linux sandbox pack-digest /srv/packs/contractors/pack.yaml` prints",
		"darwin":  "enterprise macos sandbox pack-digest /srv/packs/contractors/pack.yaml` prints",
		"windows": "`defenseclaw-gateway enterprise linux sandbox pack-digest /srv/packs/contractors/pack.yaml` (or `enterprise macos`) prints on a computer that runs sandboxes",
	} {
		got := strings.Join(cfg.SandboxAdvisories(goos), "\n")
		if !strings.Contains(got, want) || strings.Contains(got, "pack show") {
			t.Errorf("%s pin advice, want %q in:\n%s", goos, want, got)
		}
	}
}
