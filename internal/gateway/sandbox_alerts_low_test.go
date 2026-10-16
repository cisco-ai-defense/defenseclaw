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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// #1207: a sandbox verdict tells the manager (and, relayed, the daemon in
// the trailer) whether the deciding profile alerts at LOW itself; the rule
// pack's own levels do not.
func TestSandboxAlertsLowFollowsTheProfilesAlertAt(t *testing.T) {
	cases := []struct {
		name string
		cfg  func(*config.Config)
		want bool
	}{
		{"rule pack levels", func(*config.Config) {}, false},
		{"alert_at low", func(c *config.Config) { c.Guardrail.AlertAt = "low" }, true},
		{"alert_at medium", func(c *config.Config) { c.Guardrail.AlertAt = "medium" }, false},
	}
	for _, tc := range cases {
		cfg := &config.Config{DataDir: t.TempDir()}
		tc.cfg(cfg)
		api := NewAPIServer("127.0.0.1:18970", NewSidecarHealth(), nil, nil, nil, cfg)
		if got := api.sandboxAlertsLow(t.Context(), "claudecode"); got != tc.want {
			t.Fatalf("%s: alerts low = %t", tc.name, got)
		}
	}
	sink := &sandboxRelayDecisionSink{}
	sink.put(SandboxHookDecision{Action: "alert", Severity: "LOW", AlertsLow: true})
	raw, ok := sink.trailer()
	if d := sandboxrelay.ParseHookDecision(raw); !ok || d == nil || !d.AlertsLow {
		t.Fatalf("trailer %q", raw)
	}
}
