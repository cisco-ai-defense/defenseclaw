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

package extproc

import (
	"testing"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// decisionHeaderOf is the x-defenseclaw-decision value a headers response
// sets on the request, or "".
func decisionHeaderOf(r *extprocv3.ProcessingResponse) string {
	for _, h := range r.GetRequestHeaders().GetResponse().GetHeaderMutation().GetSetHeaders() {
		if h.GetHeader().GetKey() == DecisionHeader {
			return string(h.GetHeader().GetRawValue())
		}
	}
	return ""
}

// TestGAP0517BodyModeAllowedCallCarriesTheDecisionToItsDestination pins
// what the docs say for substrate-1:GAP-0517: in body mode an allowed MCP
// call goes on with the request header x-defenseclaw-decision: allow set
// at its headers (with the body override), and its body answer lets it go
// on; the answer the agent reads is the server's own. A refused call is the
// 403 with x-defenseclaw-decision: block.
func TestGAP0517BodyModeAllowedCallCarriesTheDecisionToItsDestination(t *testing.T) {
	h := newHarness(t, nil)
	c := dial(t, h)
	s, cancel := open(t, c)
	body := mcpCall("read_notes")
	r := exchange(t, s, mcpHeaders(body))
	if r.GetModeOverride() == nil || decisionHeaderOf(r) != "allow" {
		cancel()
		t.Fatalf("allowed call headers: %v (want the body override and %s: allow)", r, DecisionHeader)
	}
	if r = exchange(t, s, bodyMsg(body)); r.GetRequestBody() == nil || r.GetImmediateResponse() != nil {
		cancel()
		t.Fatalf("allowed call body: %v (want it sent on)", r)
	}
	cancel()

	h.judge.block = true
	s, cancel = open(t, c)
	defer cancel()
	body = mcpCall("delete_everything")
	if r = exchange(t, s, mcpHeaders(body)); r.GetModeOverride() == nil {
		t.Fatalf("refused call headers: %v", r)
	}
	r = exchange(t, s, bodyMsg(body))
	ir := r.GetImmediateResponse()
	if ir == nil {
		t.Fatalf("refused call body: %v (want the 403)", r)
	}
	got := ""
	for _, hv := range ir.GetHeaders().GetSetHeaders() {
		if hv.GetHeader().GetKey() == DecisionHeader {
			got = string(hv.GetHeader().GetRawValue())
		}
	}
	if got != "block" {
		t.Fatalf("refusal %s = %q, want block", DecisionHeader, got)
	}
}
