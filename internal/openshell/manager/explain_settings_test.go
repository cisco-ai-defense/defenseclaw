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

package manager

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
)

// GAP-0477: an explain of a managed-tier agent (Claude Code) shows the
// alert its sandbox raises on silent hooks, not the user tier's stop; a
// user-tier agent and an explain that names no agent keep the stop.
func TestExplainSettingsSilenceFollowsTheAgentsTier(t *testing.T) {
	cfg := &config.Config{}
	cfg.OpenShell.Admin.OnSilence = packs.OnSilenceStop
	eff, _, err := packs.Resolve(cfg, packs.Flags{Harness: "claudecode"})
	if err != nil {
		t.Fatal(err)
	}
	silence := func(tier string) (string, string) {
		for _, s := range ExplainSettings(eff, tier) {
			if s.Key == "hooks.on_silence" {
				return s.Value, s.Requested
			}
		}
		t.Fatal("no hooks.on_silence")
		return "", ""
	}
	if v, req := silence(connector.SandboxTamperTierManaged); v != packs.OnSilenceAlert || req != packs.OnSilenceStop {
		t.Fatalf("managed tier: %s (instead of %s)", v, req)
	}
	for _, tier := range []string{connector.SandboxTamperTierUser, ""} {
		if v, _ := silence(tier); v != packs.OnSilenceStop {
			t.Fatalf("tier %q: %s", tier, v)
		}
	}
}
