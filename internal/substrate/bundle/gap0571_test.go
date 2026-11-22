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

package bundle

import (
	"errors"
	"strings"
	"testing"

	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// GAP-0571: a bundle that set observe mode (top-level guardrail.mode, a
// profile's mode or a connector's mode in a profile) was refused with a
// message that did not say why ("only description and sandbox apply to
// actors", or a YAML field error). Actors always enforce; the refusal now
// names the mode key and says so.
func TestGAP0571ModeRefusalSaysActorsAlwaysEnforce(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, path string }{
		"global mode":    {"config_version: 9\nguardrail:\n  mode: observe\n  profiles:\n    eng:\n      sandbox:\n        egress_block: [x.example.com]\n", "guardrail.mode"},
		"profile mode":   {"config_version: 9\nguardrail:\n  profiles:\n    eng:\n      mode: observe\n      sandbox:\n        egress_block: [x.example.com]\n", "guardrail.profiles.eng.mode"},
		"connector mode": {"config_version: 9\nguardrail:\n  profiles:\n    eng:\n      connectors:\n        claudecode: {mode: observe}\n      sandbox:\n        egress_block: [x.example.com]\n", "guardrail.profiles.eng.connectors.claudecode.mode"},
	} {
		_, err := ParsePolicy([]byte(tc.yaml), baseConfig())
		var e *eb.Error
		if !errors.As(err, &e) || e.Code != CodeNotSubstrate {
			t.Fatalf("%s: err = %v, want %s", name, err, CodeNotSubstrate)
		}
		if e.Path != tc.path || !strings.Contains(e.Detail, "mode is not a Substrate policy field") || !strings.Contains(e.Detail, "always enforce") {
			t.Errorf("%s: path %q detail %q", name, e.Path, e.Detail)
		}
	}
	// A profile without a mode still applies.
	if _, err := ParsePolicy([]byte(policyYAML("x.example.com")), baseConfig()); err != nil {
		t.Fatalf("plain policy: %v", err)
	}
	// Another profile field keeps the general refusal.
	_, err := ParsePolicy([]byte("guardrail:\n  profiles:\n    eng: {block_at: HIGH}\n"), baseConfig())
	var e *eb.Error
	if !errors.As(err, &e) || e.Code != CodeNotSubstrate || strings.Contains(e.Detail, "mode is not") {
		t.Errorf("block_at: %v", err)
	}
}

// GAP-0571 (T6 ruling, balanced defaults): only a mode that would weaken
// enforcement is refused. mode: action is what actors already enforce
// (the LIVEGATE eng profile sets it), so it applies, as a no-op; observe
// is refused.
func TestGAP0571ActionModeAppliesObserveIsRefused(t *testing.T) {
	sb := "      sandbox:\n        egress_block: [x.example.com]\n"
	for name, tc := range map[string]struct {
		yaml    string
		refused string // the refused path; "" applies
	}{
		"global action":     {"config_version: 9\nguardrail:\n  mode: action\n  profiles:\n    eng:\n" + sb, ""},
		"global ACTION":     {"config_version: 9\nguardrail:\n  mode: ACTION\n  profiles:\n    eng:\n" + sb, ""},
		"profile action":    {"config_version: 9\nguardrail:\n  profiles:\n    eng:\n      mode: action\n" + sb, ""},
		"connector action":  {"config_version: 9\nguardrail:\n  profiles:\n    eng:\n      connectors:\n        claudecode: {mode: action}\n" + sb, ""},
		"global observe":    {"config_version: 9\nguardrail:\n  mode: observe\n  profiles:\n    eng:\n" + sb, "guardrail.mode"},
		"profile observe":   {"config_version: 9\nguardrail:\n  profiles:\n    eng:\n      mode: observe\n" + sb, "guardrail.profiles.eng.mode"},
		"connector observe": {"config_version: 9\nguardrail:\n  profiles:\n    eng:\n      mode: action\n      connectors:\n        codex: {mode: observe}\n" + sb, "guardrail.profiles.eng.connectors.codex.mode"},
		"profile other":     {"config_version: 9\nguardrail:\n  profiles:\n    eng:\n      mode: audit\n" + sb, "guardrail.profiles.eng.mode"},
	} {
		pol, err := ParsePolicy([]byte(tc.yaml), baseConfig())
		if tc.refused == "" {
			if err != nil {
				t.Errorf("%s: refused (%v), want applied", name, err)
				continue
			}
			if p := pol.Profiles["eng"]; p.Mode != "" || len(p.Connectors) != 0 {
				t.Errorf("%s: the stored profile keeps the no-op mode: %+v", name, p)
			}
			continue
		}
		var e *eb.Error
		if !errors.As(err, &e) || e.Code != CodeNotSubstrate || e.Path != tc.refused || !strings.Contains(e.Detail, "always enforce") {
			t.Errorf("%s: err = %v, want %s at %s", name, err, CodeNotSubstrate, tc.refused)
		}
	}
	// A connector entry with another field than mode keeps the general
	// refusal (only description and sandbox apply to actors).
	_, err := ParsePolicy([]byte("guardrail:\n  profiles:\n    eng:\n      connectors:\n        claudecode: {mode: action, block_at: HIGH}\n"+sb), baseConfig())
	var e *eb.Error
	if !errors.As(err, &e) || e.Code != CodeNotSubstrate || strings.Contains(e.Detail, "mode is not") {
		t.Errorf("connector block_at: %v", err)
	}
}
