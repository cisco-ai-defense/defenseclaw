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

package signin

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		connector    string
		placeholders []string
		want         Route
	}{
		{"claudecode", nil, RouteGateway},
		{"codex", nil, RouteGateway},
		{"opencode", nil, RouteGateway},
		{"copilot", nil, RouteGateway},
		{"hermes", nil, RouteGateway},
		{"cursor", nil, RouteSubscription},
		{"cursor", []string{"CURSOR_API_KEY"}, RouteVendorKey},
		{"Cursor ", []string{"CURSOR_API_KEY"}, RouteVendorKey},
		{"cursor", []string{"AMP_API_KEY"}, RouteSubscription},
		{"amp", []string{"AMP_API_KEY"}, RouteVendorKey},
		{"kiro", []string{"KIRO_API_KEY"}, RouteVendorKey},
		{"antigravity", []string{"GEMINI_API_KEY"}, RouteVendorKey},
		{"antigravity", nil, RouteSubscription},
		// Devin offers no key: a placeholder named like one changes nothing.
		{"devin", nil, RouteSubscription},
		{"devin", []string{"DEVIN_API_KEY", "WINDSURF_API_KEY"}, RouteSubscription},
		// An unknown connector is not this package's refusal to make.
		{"notaconnector", nil, RouteGateway},
	}
	for _, tc := range cases {
		if got := Classify(tc.connector, tc.placeholders); got != tc.want {
			t.Errorf("Classify(%q, %v) = %s, want %s", tc.connector, tc.placeholders, got, tc.want)
		}
	}
}

func TestEvaluateManagedRefusesSubscription(t *testing.T) {
	for _, c := range []string{"cursor", "amp", "devin", "kiro", "antigravity"} {
		d := Evaluate(c, true, nil)
		if d.Allowed || d.Code != RefusedCode || d.Route != RouteSubscription || d.Warn {
			t.Errorf("%s managed without a key: %+v, want a refusal", c, d)
		}
		if !strings.Contains(d.Message, DisplayName(c)) || !strings.Contains(d.Message, "managed") {
			t.Errorf("%s refusal message %q does not name the agent and the reason", c, d.Message)
		}
		if env := KeyEnv(c); env != "" && !strings.Contains(d.Message, env) {
			t.Errorf("%s refusal message %q does not name %s", c, d.Message, env)
		}
		if env := KeyEnv(c); env == "" && strings.Contains(d.Message, "bind") {
			t.Errorf("%s has no key route but the message tells the admin to bind one: %q", c, d.Message)
		}
	}
}

func TestEvaluateOpenSourceWarns(t *testing.T) {
	for _, c := range []string{"cursor", "amp", "devin", "kiro", "antigravity"} {
		d := Evaluate(c, false, nil)
		if !d.Allowed || !d.Warn || d.Code != "" || d.Route != RouteSubscription {
			t.Errorf("%s open source without a key: %+v, want an allowed warning", c, d)
		}
		if !strings.Contains(d.Message, "snapshot") {
			t.Errorf("%s warning %q does not say the token is kept in snapshots", c, d.Message)
		}
	}
}

func TestEvaluateOtherRoutesAreUntouched(t *testing.T) {
	for _, managed := range []bool{true, false} {
		for _, c := range []string{"claudecode", "codex", "opencode", "copilot", "hermes"} {
			if d := Evaluate(c, managed, nil); !d.Allowed || d.Warn || d.Message != "" || d.Route != RouteGateway {
				t.Errorf("%s managed=%v: %+v, want allowed with no message", c, managed, d)
			}
		}
		for c, env := range map[string]string{"cursor": "CURSOR_API_KEY", "kiro": "KIRO_API_KEY", "antigravity": "GEMINI_API_KEY"} {
			if d := Evaluate(c, managed, []string{env}); !d.Allowed || d.Warn || d.Message != "" || d.Route != RouteVendorKey {
				t.Errorf("%s managed=%v with %s bound: %+v, want allowed on the vendor key", c, managed, env, d)
			}
		}
	}
}

func TestKnownAndNames(t *testing.T) {
	for _, c := range []string{"claudecode", "codex", "opencode", "copilot", "hermes", "cursor", "amp", "devin", "kiro", "antigravity"} {
		if !Known(c) {
			t.Errorf("%s is not known", c)
		}
		if DisplayName(c) == c {
			t.Errorf("%s has no display name", c)
		}
	}
	if Known("nope") || DisplayName("nope") != "nope" {
		t.Error("an unknown connector must keep its own name")
	}
}

// Amp must own the folder that holds its plugin (it chmods it at every
// start), so the agent can remove DefenseClaw's hook: managed refuses it even
// on a vendor key, open source warns.
func TestAmpHookRegistrationRule(t *testing.T) {
	d := Evaluate("amp", true, []string{"AMP_API_KEY"})
	if d.Allowed || d.Code != TamperRefusedCode || d.Route != RouteVendorKey || !IsRefusalCode(d.Code) {
		t.Fatalf("amp managed on a key: %+v, want a tamper refusal", d)
	}
	d = Evaluate("amp", false, []string{"AMP_API_KEY"})
	if !d.Allowed || !d.Warn || !strings.Contains(d.Message, "remove the hook") || strings.Contains(d.Message, "snapshot") {
		t.Fatalf("amp open source on a key: %+v, want a tamper warning only", d)
	}
	d = Evaluate("amp", false, nil)
	if !d.Warn || !strings.Contains(d.Message, "snapshot") || !strings.Contains(d.Message, "remove the hook") {
		t.Fatalf("amp open source without a key: %+v, want both warnings", d)
	}
	if !IsRefusalCode(RefusedCode) || IsRefusalCode("actor_not_registered") {
		t.Error("IsRefusalCode")
	}
}
