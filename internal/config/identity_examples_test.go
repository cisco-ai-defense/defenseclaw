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
	"os"
	"path/filepath"
	"testing"
)

// The Active Directory example in the identity kit is also the main example in
// the docs. It must load with the managed sandbox keys, every profile's floor
// must resolve, and its default_profile must be at least as strict as every
// assigned profile. A directory outage refuses requests whose assignments
// need the missing fact, naming it; default_profile applies only when no
// assignment needs it. A looser default still teaches a gap for unassigned
// accounts.
func TestADSandboxProfilesExampleLoadsWithoutDefaultWarnings(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	raw, err := os.ReadFile(filepath.Join("..", "..", "packaging", "identity", "ad", "sandbox-profiles.example.yaml"))
	if err != nil {
		t.Fatalf("read the example: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := LoadRuntimeV8InspectionCandidateFromBytes(path, raw)
	if err != nil {
		t.Fatalf("the AD example does not load: %v", err)
	}
	for _, name := range []string{"contractors", "engineering", "offline-floor"} {
		if _, ok := cfg.Guardrail.Profiles[name]; !ok {
			t.Fatalf("the example lost its %q profile", name)
		}
		if _, _, err := cfg.SandboxFloor(name); err != nil {
			t.Errorf("floor of %q: %v", name, err)
		}
	}
	if got := cfg.Guardrail.DefaultProfile; got != "offline-floor" {
		t.Fatalf("default_profile = %q, want offline-floor", got)
	}
	if w := cfg.SandboxDefaultProfileWarnings(); len(w) != 0 {
		t.Errorf("the AD example's default_profile is looser than an assigned profile:\n%v", w)
	}
}
