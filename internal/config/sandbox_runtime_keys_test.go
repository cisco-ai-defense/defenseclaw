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
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSandboxRuntimeKeysValidate(t *testing.T) {
	cases := []struct {
		name string
		in   SandboxAdminConfig
		want string
	}{
		{"valid", SandboxAdminConfig{Runtimes: []string{"substrate"}, SandboxClass: "microvm", IdleSuspendAfter: "15m",
			UnattendedAsks: "queue", AskTimeout: "2h", ActorSecrets: []string{"db-password"}}, ""},
		{"empty runtimes", SandboxAdminConfig{Runtimes: []string{}}, "sandbox.runtimes: an empty list is refused"},
		{"bad runtime", SandboxAdminConfig{Runtimes: []string{"docker"}}, `sandbox.runtimes[0]: "docker" must be openshell or substrate`},
		{"bad class", SandboxAdminConfig{SandboxClass: "kata"}, `sandbox.sandbox_class "kata" must be one of gvisor, microvm`},
		{"bad asks", SandboxAdminConfig{UnattendedAsks: "allow"}, `sandbox.unattended_asks "allow" must be one of deny, queue`},
		{"short idle", SandboxAdminConfig{IdleSuspendAfter: "30s"}, `sandbox.idle_suspend_after "30s" must be at least 1m`},
		{"days idle", SandboxAdminConfig{IdleSuspendAfter: "2d"}, `sandbox.idle_suspend_after "2d" must be a Go duration such as 30m`},
		{"long ask", SandboxAdminConfig{AskTimeout: "25h"}, `sandbox.ask_timeout "25h" must be at most 24h0m0s`},
		{"empty secrets", SandboxAdminConfig{ActorSecrets: []string{}}, "sandbox.actor_secrets: an empty list is refused"},
		{"bad secret", SandboxAdminConfig{ActorSecrets: []string{"../etc/passwd"}}, `sandbox.actor_secrets[0]: "../etc/passwd" must be a secret key`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			err := in.validateAs("sandbox")
			if tc.want == "" {
				if err != nil {
					t.Fatalf("validateAs = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateAs = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSandboxRuntimeKeysScope(t *testing.T) {
	host := SandboxAdminConfig{SandboxClass: "gvisor", ActorSecrets: []string{"x-token"}, Runtimes: []string{"substrate"}}
	err := host.hostScopeError("admin")
	if err == nil || !strings.Contains(err.Error(), "admin.sandbox_class is an Agent Substrate key") ||
		!strings.Contains(err.Error(), "admin.actor_secrets is an Agent Substrate key") || strings.Contains(err.Error(), "runtimes") {
		t.Fatalf("hostScopeError = %v", err)
	}
	yes := true
	cluster := SandboxAdminConfig{AllowMount: &yes, DriverFallback: "none", Locked: []string{"pack", "workdir.mode"},
		RequireCopyFor: []string{"~/src/**"}, Runtimes: []string{"substrate"}, SandboxClass: "microvm"}
	err = cluster.substrateScopeError("admin")
	for _, want := range []string{"admin.allow_mount is a host sandbox key", "admin.driver_fallback", "admin.require_copy_for",
		"admin.locked[1] (workdir.mode)"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("substrateScopeError = %v, want %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "sandbox_class") || strings.Contains(err.Error(), "locked[0]") {
		t.Fatalf("substrateScopeError refused a cluster key: %v", err)
	}
	if err := (&SandboxAdminConfig{}).substrateScopeError("admin"); err != nil {
		t.Fatalf("an empty floor was refused: %v", err)
	}
}

func TestSandboxRuntimeKeysTighten(t *testing.T) {
	base := SandboxAdminConfig{Runtimes: []string{"openshell", "substrate"}, SandboxClass: "gvisor", IdleSuspendAfter: "30m",
		UnattendedAsks: "queue", AskTimeout: "1h", ActorSecrets: []string{"a", "b"}}
	got, err := TightenSandboxAdmin(base, &SandboxAdminConfig{Runtimes: []string{"substrate"}, SandboxClass: "microvm",
		IdleSuspendAfter: "10m", UnattendedAsks: "deny", AskTimeout: "2h", ActorSecrets: []string{"b", "c"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Runtimes, []string{"substrate"}) || got.SandboxClass != "microvm" || got.IdleSuspendAfter != "10m" ||
		got.UnattendedAsks != "deny" || got.AskTimeout != "1h" || !slices.Equal(got.ActorSecrets, []string{"b"}) {
		t.Fatalf("tightened = %+v", got)
	}
	// A profile never loosens: gvisor under microvm, queue under deny.
	got, err = TightenSandboxAdmin(SandboxAdminConfig{SandboxClass: "microvm", UnattendedAsks: "deny"},
		&SandboxAdminConfig{SandboxClass: "gvisor", UnattendedAsks: "queue"})
	if err != nil || got.SandboxClass != "microvm" || got.UnattendedAsks != "deny" {
		t.Fatalf("loosened: %+v, %v", got, err)
	}
	// Unset base: the profile's values apply.
	got, err = TightenSandboxAdmin(SandboxAdminConfig{}, &SandboxAdminConfig{UnattendedAsks: "queue", ActorSecrets: []string{"a"}})
	if err != nil || got.UnattendedAsks != "queue" || !slices.Equal(got.ActorSecrets, []string{"a"}) {
		t.Fatalf("unset base: %+v, %v", got, err)
	}
	// Disjoint actor_secrets expose nothing; disjoint runtimes contradict.
	got, err = TightenSandboxAdmin(SandboxAdminConfig{ActorSecrets: []string{"a"}}, &SandboxAdminConfig{ActorSecrets: []string{"b"}})
	if err != nil || got.ActorSecrets == nil || len(got.ActorSecrets) != 0 {
		t.Fatalf("disjoint actor_secrets: %#v, %v", got.ActorSecrets, err)
	}
	_, err = TightenSandboxAdmin(SandboxAdminConfig{Runtimes: []string{"openshell"}}, &SandboxAdminConfig{Runtimes: []string{"substrate"}})
	var contradiction *SandboxPolicyContradictionError
	if !errors.As(err, &contradiction) || contradiction.Field != "runtimes" || !strings.Contains(err.Error(), "leaves no runtime") {
		t.Fatalf("disjoint runtimes: %v", err)
	}
	// The base is not changed by a tighten.
	if !slices.Equal(base.Runtimes, []string{"openshell", "substrate"}) || !slices.Equal(base.ActorSecrets, []string{"a", "b"}) {
		t.Fatalf("base changed: %+v", base)
	}
}

func TestSandboxRuntimeKeysEffective(t *testing.T) {
	var unset SandboxAdminConfig
	if !unset.AllowsRuntime("openshell") || !unset.AllowsRuntime("substrate") || unset.SubstrateOnly() {
		t.Fatal("unset runtimes must allow both")
	}
	only := SandboxAdminConfig{Runtimes: []string{"substrate"}}
	if only.AllowsRuntime("openshell") || !only.SubstrateOnly() {
		t.Fatal("runtimes [substrate] must refuse openshell")
	}
	if unset.EffectiveSandboxClass("gvisor") != "gvisor" || (SandboxAdminConfig{SandboxClass: "microvm"}).EffectiveSandboxClass("gvisor") != "microvm" ||
		(SandboxAdminConfig{SandboxClass: "gvisor"}).EffectiveSandboxClass("microvm") != "microvm" {
		t.Fatal("EffectiveSandboxClass must take the stronger class")
	}
	if !SandboxClassSatisfies("microvm", "gvisor") || SandboxClassSatisfies("gvisor", "microvm") || !SandboxClassSatisfies("gvisor", "") {
		t.Fatal("SandboxClassSatisfies")
	}
	if unset.EffectiveIdleSuspendAfter(30*time.Minute) != 30*time.Minute ||
		(SandboxAdminConfig{IdleSuspendAfter: "2h"}).EffectiveIdleSuspendAfter(0) != 2*time.Hour {
		t.Fatal("EffectiveIdleSuspendAfter")
	}
	if unset.EffectiveUnattendedAsks("") != "deny" || unset.EffectiveUnattendedAsks("queue") != "queue" ||
		(SandboxAdminConfig{UnattendedAsks: "queue"}).EffectiveUnattendedAsks("deny") != "queue" ||
		(SandboxAdminConfig{UnattendedAsks: "deny"}).EffectiveUnattendedAsks("queue") != "deny" {
		t.Fatal("EffectiveUnattendedAsks")
	}
	if unset.EffectiveAskTimeout(30*time.Minute) != 30*time.Minute ||
		(SandboxAdminConfig{AskTimeout: "5m"}).EffectiveAskTimeout(30*time.Minute) != 5*time.Minute {
		t.Fatal("EffectiveAskTimeout")
	}
}

// The floor digest of a floor without the new keys is unchanged, and the
// Substrate-only keys never change a computer's floor digest.
func TestSandboxRuntimeKeysFloorDigest(t *testing.T) {
	yes := true
	floor := SandboxAdminConfig{RequiredFor: []string{"claudecode"}, AllowMount: &yes, EgressBlock: []string{"example.com"}}
	plain, err := sandboxFloorDigest(floor, "")
	if err != nil {
		t.Fatal(err)
	}
	// Pinned before the runtime keys existed (feat/substrate 0fd66d830d).
	const before = "sha256:" + floorDigestBeforeRuntimeKeys
	if plain != before {
		t.Fatalf("digest of a floor without runtime keys changed: %s, want %s", plain, before)
	}
	withSubstrate := floor
	withSubstrate.SandboxClass, withSubstrate.UnattendedAsks, withSubstrate.ActorSecrets = "microvm", "queue", []string{"a"}
	withSubstrate.IdleSuspendAfter, withSubstrate.AskTimeout = "10m", "1h"
	if got, _ := sandboxFloorDigest(withSubstrate, ""); got != plain {
		t.Fatalf("Substrate-only keys changed the host floor digest: %s", got)
	}
	withRuntimes := floor
	withRuntimes.Runtimes = []string{"substrate"}
	if got, _ := sandboxFloorDigest(withRuntimes, ""); got == plain {
		t.Fatal("runtimes must change the floor digest: it gates host runs")
	}
}

func TestSubstrateProfilesTightenSubstrateAdmin(t *testing.T) {
	cfg := &Config{}
	cfg.Substrate.LauncherAtespaces = map[string][]string{"eng": {"eng-web"}}
	cfg.Substrate.Admin.Runtimes = []string{"openshell"}
	cfg.Guardrail.Profiles = map[string]GuardrailProfile{"eng": {Sandbox: &SandboxAdminConfig{Runtimes: []string{"substrate"}}}}
	err := cfg.validateSubstrateProfiles()
	if err == nil || !strings.Contains(err.Error(), `guardrail.profiles["eng"].sandbox: combined with substrate.admin`) {
		t.Fatalf("validateSubstrateProfiles = %v", err)
	}
	cfg.Substrate.Admin.Runtimes = nil
	if err := cfg.validateSubstrateProfiles(); err != nil {
		t.Fatalf("validateSubstrateProfiles = %v", err)
	}
}

// Upgrade: a 1.0.9 config (no runtime keys) loads unchanged, and a config
// with every key loads through the daemon loader (schema and validation)
// and keeps the values.
func TestSandboxRuntimeKeysLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigName)
	src := "config_version: 9\n" +
		"guardrail:\n  profiles:\n    eng:\n      mode: action\n      sandbox:\n" +
		"        required_for: [claudecode]\n        runtimes: [substrate]\n        sandbox_class: MicroVM\n" +
		"        idle_suspend_after: 20m\n        unattended_asks: queue\n        ask_timeout: 45m\n" +
		"        actor_secrets: [db-password]\n" +
		"data_dir: " + dir + "\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuntimeV8File(path); err != nil {
		t.Fatalf("LoadRuntimeV8File = %v", err)
	}
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile = %v", err)
	}
	s := cfg.Guardrail.Profiles["eng"].Sandbox
	if s == nil || !slices.Equal(s.Runtimes, []string{"substrate"}) || s.SandboxClass != "microvm" || s.IdleSuspendAfter != "20m" ||
		s.UnattendedAsks != "queue" || s.AskTimeout != "45m" || !slices.Equal(s.ActorSecrets, []string{"db-password"}) {
		t.Fatalf("sandbox = %+v", s)
	}

	old := "config_version: 9\nguardrail:\n  profiles:\n    eng:\n      mode: action\n      sandbox:\n        required_for: [claudecode]\n" +
		"data_dir: " + dir + "\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if s := cfg.Guardrail.Profiles["eng"].Sandbox; s.Runtimes != nil || s.ActorSecrets != nil || s.SandboxClass != "" || !s.AllowsRuntime("openshell") {
		t.Fatalf("a 1.0.9 profile gained runtime keys: %+v", s)
	}

	host := "config_version: 9\nopenshell:\n  admin:\n    sandbox_class: microvm\ndata_dir: " + dir + "\n"
	if err := os.WriteFile(path, []byte(host), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromFile(path); err == nil || !strings.Contains(err.Error(), "admin.sandbox_class is an Agent Substrate key") {
		t.Fatalf("openshell.admin sandbox_class: %v", err)
	}
	cluster := "config_version: 9\nsubstrate:\n  admin:\n    allow_mount: true\ndata_dir: " + dir + "\n"
	if err := os.WriteFile(path, []byte(cluster), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromFile(path); err == nil || !strings.Contains(err.Error(), "admin.allow_mount is a host sandbox key") {
		t.Fatalf("substrate.admin allow_mount: %v", err)
	}
}

const floorDigestBeforeRuntimeKeys = "a69f5bdb7cb00a30bf8bd89d901b5048929d8fd4ec28e18ea099c16a26abcd37"
