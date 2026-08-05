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

package gateway

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

type numbatCoverageManifest struct {
	Source struct {
		Repository   string `json:"repository"`
		Commit       string `json:"commit"`
		CatalogRules int    `json:"catalog_rules"`
	} `json:"source"`
	DefenseClawBase string               `json:"defenseclaw_base"`
	Rules           []numbatCoverageRule `json:"rules"`
}

type numbatCoverageRule struct {
	UpstreamID     string   `json:"upstream_id"`
	Status         string   `json:"status"`
	DefenseClawIDs []string `json:"defenseclaw_ids"`
	Rationale      string   `json:"rationale"`
}

// pinnedNumbatRuleIDs is the built-in catalog snapshot at source.commit. Keep
// it independent from the manifest entries so a fabricated or omitted ID
// cannot preserve the count while silently changing the claimed coverage set.
var pinnedNumbatRuleIDs = []string{
	"chain.guardrails_off_then_egress",
	"chain.permission_denied_then_runtime_bypass",
	"chain.privilege_discovery_then_elevation",
	"chain.secret_manager_read_then_egress",
	"chain.secret_read_then_egress",
	"chain.workload_identity_then_lateral_execution",
	"exec.agent_runtime_bypass_flags",
	"exec.destructive_recursive_delete",
	"exec.download_pipe_shell",
	"exec.encoded_payload_shell",
	"exec.reverse_shell",
	"exec.reverse_tunnel",
	"exfil.curl_post_file",
	"exfil.dns_tunnel_exec",
	"exfil.env_capture_to_network",
	"exfil.secret_read_and_egress_oneliner",
	"impact.cryptomining_launch",
	"impact.disk_wipe",
	"impact.fork_bomb",
	"impact.mass_process_termination",
	"integrity.git_hooks_bypass",
	"integrity.history_tamper",
	"lateral.workload_exec",
	"persistence.git_hook_write",
	"persistence.privileged_account_change",
	"persistence.scheduler_install",
	"persistence.shell_profile_write",
	"persistence.ssh_authorized_keys",
	"persistence.ssh_authorized_keys_command",
	"privilege.access_control_mutation",
	"privilege.container_host_escape",
	"privilege.container_runtime_socket_access",
	"privilege.elevated_shell",
	"privilege.host_namespace_entry",
	"privilege.sudoers_tamper",
	"recon.cloud_metadata",
	"recon.network_sweep",
	"recon.privilege_escalation",
	"secrets.agent_read_env",
	"secrets.browser_session_store_read",
	"secrets.cloud_credential_read",
	"secrets.cloud_secret_manager_read",
	"secrets.developer_credential_read",
	"secrets.process_environment_read",
	"secrets.read_private_key",
	"secrets.workload_identity_token_read",
	"source.git_config_exec",
	"source.git_remote_tamper",
	"tamper.agent_config_write",
	"tamper.detector_state_write",
	"tamper.guardrails_off",
}

func TestNumbatCapabilityCoverageManifest(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("testdata/security_suite/toolcall/numbat_coverage.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest numbatCoverageManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Source.Repository != "https://github.com/perplexityai/numbat" {
		t.Fatalf("unexpected Numbat source repository %q", manifest.Source.Repository)
	}
	if manifest.Source.Commit != "0e41ad66f5557f412eae330576271f2ee809d3de" {
		t.Fatalf("unexpected Numbat source commit %q", manifest.Source.Commit)
	}
	if manifest.DefenseClawBase != "f00315b45e825fcc79ee313d45b05994973b8be4" {
		t.Fatalf("unexpected DefenseClaw base %q", manifest.DefenseClawBase)
	}
	if manifest.Source.CatalogRules != 51 || len(manifest.Rules) != 51 {
		t.Fatalf("catalog/rules = %d/%d, want 51/51", manifest.Source.CatalogRules, len(manifest.Rules))
	}
	gotUpstreamIDs := make([]string, 0, len(manifest.Rules))
	for _, rule := range manifest.Rules {
		gotUpstreamIDs = append(gotUpstreamIDs, rule.UpstreamID)
	}
	if !slices.Equal(gotUpstreamIDs, pinnedNumbatRuleIDs) {
		t.Fatalf("manifest upstream IDs do not match the pinned Numbat catalog\ngot:  %q\nwant: %q", gotUpstreamIDs, pinnedNumbatRuleIDs)
	}

	knownIDs := make(map[string]struct{})
	generation := snapshotRulePackGeneration("")
	if generation == nil {
		t.Fatal("default rule generation is unavailable")
	}
	for _, category := range generation.categories {
		for _, rule := range category.Rules {
			knownIDs[rule.ID] = struct{}{}
		}
	}
	for ownerID, owner := range semanticOwners {
		knownIDs[ownerID] = struct{}{}
		for _, aliases := range [][]string{
			owner.equivalentAliases,
			owner.matchedOnlyAliases,
			owner.fallbackAliasesOnMatch,
			owner.unmatchedClaims,
		} {
			for _, alias := range aliases {
				knownIDs[alias] = struct{}{}
			}
		}
	}
	for _, definition := range guardrail.ToolChainDefinitions() {
		knownIDs[definition.ID] = struct{}{}
	}

	allowedStatuses := map[string]struct{}{
		"exact": {}, "equivalent": {}, "partial": {}, "deferred": {},
	}
	wantCounts := map[string]int{
		"exact": 0, "equivalent": 16, "partial": 34, "deferred": 1,
	}
	gotCounts := make(map[string]int, len(wantCounts))
	seen := make(map[string]struct{}, len(manifest.Rules))
	previousID := ""
	for index, rule := range manifest.Rules {
		if rule.UpstreamID == "" || rule.Rationale == "" {
			t.Fatalf("rule %d has an empty ID or rationale: %+v", index, rule)
		}
		if _, ok := allowedStatuses[rule.Status]; !ok {
			t.Fatalf("rule %q has unsupported status %q", rule.UpstreamID, rule.Status)
		}
		if _, ok := seen[rule.UpstreamID]; ok {
			t.Fatalf("duplicate upstream rule %q", rule.UpstreamID)
		}
		seen[rule.UpstreamID] = struct{}{}
		if previousID != "" && rule.UpstreamID < previousID {
			t.Fatalf("rules are not sorted: %q appears after %q", rule.UpstreamID, previousID)
		}
		previousID = rule.UpstreamID
		gotCounts[rule.Status]++
		if len(rule.DefenseClawIDs) == 0 {
			t.Fatalf("rule %q has no DefenseClaw owner or reserved ID", rule.UpstreamID)
		}
		if slices.Contains(rule.DefenseClawIDs, "") {
			t.Fatalf("rule %q has an empty DefenseClaw ID", rule.UpstreamID)
		}
		if rule.Status == "deferred" {
			continue
		}
		for _, ruleID := range rule.DefenseClawIDs {
			if _, ok := knownIDs[ruleID]; !ok {
				t.Errorf("rule %q references unknown DefenseClaw ID %q", rule.UpstreamID, ruleID)
			}
		}
	}
	for status, want := range wantCounts {
		if got := gotCounts[status]; got != want {
			t.Errorf("%s count = %d, want %d", status, got, want)
		}
	}
}
