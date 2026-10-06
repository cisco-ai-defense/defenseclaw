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
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// TestPolicyDigestReportsWhetherTheGatewayAppliedIt: the lifecycle result's
// policy block is applied only when the running gateway's /health reports
// the digest the installed config computes to, and says why when it
// rejected a reload or the config was edited outside the lifecycle
// (GAP-0093, GAP-0145).
func TestPolicyDigestReportsWhetherTheGatewayAppliedIt(t *testing.T) {
	reported := "sha256:" + strings.Repeat("a", 64)
	other := "sha256:" + strings.Repeat("b", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"policy":{"effective_digest":"` + reported + `","last_reload_error":"digest mismatch"}}`))
	}))
	defer server.Close()
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	cfg := &config.Config{}
	cfg.Gateway.APIBind = host
	cfg.Gateway.APIPort, _ = strconv.Atoi(port)
	if got := gatewayReportedPolicy(cfg); got.EffectiveDigest != reported || got.LastReloadError != "digest mismatch" {
		t.Fatalf("gateway reported policy = %+v", got)
	}

	run := func(change bool, out string) (*enterprisestatus.Result, *enterprisestatus.PolicyState) {
		result := enterprisestatus.New("ensure", "standalone", "windows", "1.0.0")
		state := applyEnterprisePolicyReport(result, []byte(out), change)
		return result, state
	}
	codes := func(result *enterprisestatus.Result) string {
		var out []string
		for _, warning := range result.Warnings {
			out = append(out, warning.Code)
		}
		return strings.Join(out, ",")
	}
	report := func(computed, gateway, extra string) string {
		return `{"effective_digest":"` + computed + `","config_generation":4,"config_generation_recorded":true,` +
			`"gateway_reported_digest":"` + gateway + `"` + extra + `}`
	}

	if result, state := run(true, report(reported, reported, "")); state == nil || !state.Applied || state.ConfigGeneration != 4 || codes(result) != "" {
		t.Fatalf("applied: state=%+v warnings=%s", state, codes(result))
	}
	if result, state := run(true, report(other, reported, "")); state == nil || state.Applied || codes(result) != "policy_not_applied" {
		t.Fatalf("stale gateway after a change: state=%+v warnings=%s", state, codes(result))
	}
	if result, state := run(false, report(other, reported, "")); state == nil || state.Applied || codes(result) != "" {
		t.Fatalf("status reports a stale gateway without a warning: state=%+v warnings=%s", state, codes(result))
	}
	// The gateway rejected the last reload: not applied, and every action says so.
	if result, state := run(false, report(reported, reported, `,"gateway_last_reload_error":"digest mismatch"`)); state == nil ||
		state.Applied || state.LastReloadError != "digest mismatch" || codes(result) != "policy_reload_failed" {
		t.Fatalf("rejected reload: state=%+v warnings=%s", state, codes(result))
	}
	// A config.yaml nobody recorded.
	if result, state := run(false, strings.Replace(report(reported, reported, ""), `"config_generation_recorded":true`, `"config_generation_recorded":false`, 1)); state == nil ||
		!state.ConfigUnrecorded || codes(result) != "config_edited_outside_lifecycle" {
		t.Fatalf("unrecorded config: state=%+v warnings=%s", state, codes(result))
	}
	// No generation recorded yet is not an edit.
	if result, state := run(false, `{"effective_digest":"`+reported+`","config_generation":0,"config_generation_recorded":false,"gateway_reported_digest":"`+reported+`"}`); state == nil ||
		state.ConfigUnrecorded || codes(result) != "" {
		t.Fatalf("no generation yet: state=%+v warnings=%s", state, codes(result))
	}
	// A policy that cannot be built is a warning, not a policy block.
	if result, state := run(false, `{"error":"rule pack \"p\": digest does not match","gateway_reported_digest":"`+reported+`"}`); state != nil ||
		result.Policy != nil || codes(result) != "policy_not_buildable" {
		t.Fatalf("unbuildable policy: state=%+v warnings=%s", state, codes(result))
	}
	// An earlier release prints nothing useful: no block and no warning.
	if result, state := run(true, `{}`); state != nil || codes(result) != "" {
		t.Fatalf("report without a digest: state=%+v warnings=%s", state, codes(result))
	}
}
