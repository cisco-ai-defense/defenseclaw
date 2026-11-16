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

package cli

import (
	"encoding/json"
	"strings"

	"gopkg.in/yaml.v3"
)

// A guardian can discover Codex after install and create its hooks while
// deployment.json still records Codex disabled. Matching config bytes do not
// prove that the lifecycle owns the machine policy (GAP-0360). Missing or
// malformed evidence also requires the validating lifecycle transaction.
func windowsConfigCodexTargetNeedsReconcile(supplied, metadata []byte) bool {
	want, ok := windowsConfigProtectsCodex(supplied)
	var recorded struct {
		Enabled *bool `json:"codex_target_enabled"`
	}
	if !ok || json.Unmarshal(metadata, &recorded) != nil || recorded.Enabled == nil {
		return true
	}
	return want != *recorded.Enabled
}

// On Windows the lifecycle transaction, not the hook guardian, owns Codex's
// machine policy: C:\ProgramData\OpenAI\Codex\requirements.toml, the
// ownership record and access-list preimage DefenseClaw keeps for it, and
// codex_target_enabled in the deployment record. The transaction snapshots
// the administrator's file before DefenseClaw first writes it and restores it
// when Codex protection is turned off. A config change that turns Codex
// protection on or off therefore goes to that transaction (an upgrade, or a
// repair with the config when the run has no payload), a signed bundle's
// included. Applied in the running gateway, the guardian wrote the
// Codex requirements and their ownership record while the deployment record
// still said Claude-only, so the post-apply verify refused the deployment
// ("Claude-only deployment retains stale DefenseClaw Codex ownership state")
// and the bundle failed (GAP-0033).

// windowsConfigCodexTargetChanged reports whether exactly one of the
// installed and the supplied config protects Codex. A config either side
// cannot parse counts as a change: the transaction validates it and refuses
// it, and the running gateway never gets it.
func windowsConfigCodexTargetChanged(installed, supplied []byte) bool {
	before, beforeOK := windowsConfigProtectsCodex(installed)
	after, afterOK := windowsConfigProtectsCodex(supplied)
	if !beforeOK || !afterOK {
		return true
	}
	return before != after
}

// windowsConfigProtectsCodex mirrors enterprisehooks'
// effectiveWindowsHookConnectors for Codex: a guardrail.connectors entry for
// Codex, or a guardrail.connector of codex, enables it unless the entry says
// enabled: false. Names compare case-insensitively. ok is false for a config
// that does not parse.
func windowsConfigProtectsCodex(raw []byte) (enabled, ok bool) {
	var document struct {
		Guardrail struct {
			Connector  string `yaml:"connector"`
			Connectors map[string]*struct {
				Enabled *bool `yaml:"enabled"`
			} `yaml:"connectors"`
		} `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return false, false
	}
	listed, disabled := false, false
	for name, entry := range document.Guardrail.Connectors {
		if !strings.EqualFold(strings.TrimSpace(name), "codex") {
			continue
		}
		if entry != nil && entry.Enabled != nil && !*entry.Enabled {
			disabled = true
			continue
		}
		listed = true
	}
	if strings.EqualFold(strings.TrimSpace(document.Guardrail.Connector), "codex") {
		listed = true
	}
	return listed && !disabled, true
}
