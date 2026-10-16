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
	"strings"
	"testing"
)

// GAP-0510: on a managed standalone host a locked openshell.pack becomes the
// required pack of every floor that names none (SandboxManagedFloor), so the
// load judges it with the profile pack check, as each run does; a refusal
// names openshell.pack and keeps the check's own words (the field and the
// fix). Without the lock, with a floor pack of its own, or off a standalone
// managed host the pack is not every floor's required pack and is not judged
// here.
func TestValidateLockedSandboxPack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*Config)
		calls string
		// lock is the lock the refusal names (pass-6 review: a profile's
		// lock was reported as openshell.admin.locked).
		lock string
	}{
		{name: "openshell.admin locks the pack", edit: func(c *Config) { c.OpenShell.Admin.Locked = []string{"pack"} }, calls: ">wk-locked>",
			lock: `openshell.pack "wk-locked": openshell.admin.locked lists pack, so it is the required pack of every sandbox`},
		{name: "a profile locks the pack", edit: func(c *Config) {
			c.Guardrail.Profiles["engineering"].Sandbox.Locked = []string{"pack"}
		}, calls: ">wk-locked>",
			lock: `openshell.pack "wk-locked": guardrail.profiles["engineering"].sandbox.locked lists pack, so it is the required pack of that profile's sandboxes`},
		{name: "not locked", edit: func(*Config) {}},
		{name: "the floor names its own pack", edit: func(c *Config) {
			c.OpenShell.Admin.Locked, c.OpenShell.Admin.RequiredPack = []string{"pack"}, "strict"
		}},
		{name: "not a standalone managed host", edit: func(c *Config) {
			c.OpenShell.Admin.Locked = []string{"pack"}
			c.DeploymentMode, c.Enterprise.Profile = "", ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sandboxProfilesFixture()
			cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
			cfg.OpenShell.Pack = "wk-locked"
			tc.edit(cfg)
			var calls []string
			old := SandboxProfilePackCheck
			t.Cleanup(func() { SandboxProfilePackCheck = old })
			SandboxProfilePackCheck = func(_ *Config, base, profile, digest string) error {
				calls = append(calls, base+">"+profile+">"+digest)
				if profile == "wk-locked" {
					return errors.New("sandbox policy: the required pack wk-locked of your sandbox policy is looser than the default pack wk-locked in workspace.mode (managed computers run sandboxes on a copy of the project: set workspace.mode: copy in the pack)")
				}
				return nil
			}
			err := cfg.ValidateGuardrailProfiles()
			if got := strings.Join(calls, ","); got != tc.calls {
				t.Fatalf("calls = %q, want %q (err %v)", got, tc.calls, err)
			}
			if tc.calls == "" {
				if err != nil {
					t.Fatalf("ValidateGuardrailProfiles() = %v", err)
				}
				return
			}
			for _, want := range []string{tc.lock, "in workspace.mode", "set workspace.mode: copy in the pack"} {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("ValidateGuardrailProfiles() = %v, want %q", err, want)
				}
			}
		})
	}
}
