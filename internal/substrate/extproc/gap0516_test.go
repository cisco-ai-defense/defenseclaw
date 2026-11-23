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
	"bytes"
	"context"
	"slices"
	"strconv"
	"testing"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/proto"
)

// bigMCPPost is a POST to the MCP host that states a 2,000,000 byte body
// (the J29 stock-headers-only step 4 request).
func bigMCPPost(h *harness) *Request {
	m := mcpFramed(false, ":method", "POST", "content-type", "application/json", "content-length", strconv.Itoa(2000000))
	return h.eng.requestFrom(m, m.GetRequestHeaders())
}

// TestGAP0516StockFilterOverCapIsDecidedOnHeaders is substrate-1:GAP-0516.
// Under body_inspection auto with no body seen yet (stock Agent Substrate
// v1.0.0, the chart default), a POST over the cap to an MCP host is not
// refused as body_uninspectable / over_cap from its headers: it asks for
// its body like any other body there, and when the filter forwards it
// unread the event is the body_not_received alert every body on a stock
// filter gets, not body_over_cap.
func TestGAP0516StockFilterOverCapIsDecidedOnHeaders(t *testing.T) {
	h := newHarness(t, nil) // closed, auto, no body seen: as on cluster t29a
	if st := h.eng.BodyModeStatus(); st != "unknown" {
		t.Fatalf("body mode %s", st)
	}
	v := h.eng.DecideHeaders(context.Background(), bigMCPPost(h))
	if !v.Allow || !v.WantBody || v.BodyOverCap || v.Category == CategoryBodyUninspected {
		t.Fatalf("stated length over the cap, no body seen: %+v (want an allow that asks for the body)", v)
	}

	// Over the wire: the headers get the body override, and a stream that
	// ends without the body (the stock filter sent it on) is the usual alert.
	c := dial(t, h)
	s, cancel := open(t, c)
	r := exchange(t, s, mcpFramed(false, ":method", "POST", "content-type", "application/json",
		"content-length", strconv.Itoa(2000000)))
	if r.GetImmediateResponse() != nil || !proto.Equal(r.GetModeOverride(), overrideMode()) {
		cancel()
		t.Fatalf("headers: %v (want continue with the body override)", r)
	}
	_ = s.CloseSend()
	_, _ = s.Recv()
	cancel()
	ev := waitEvents(t, h.events, 1)[0]
	if ev.Decision != "allow" || !ev.Alert || ev.BodyOverCap || ev.BodyInspected ||
		!slices.Contains(ev.Findings, "body_not_received:"+signalEOF) || slices.Contains(ev.Findings, "body_over_cap") {
		t.Fatalf("event: %+v (want allow, alert body_not_received, no body_over_cap)", ev)
	}
}

// The filters that send bodies keep refusing a body over the cap: a body
// that comes over the cap is refused in DecideBody, and once a body has
// arrived (or with on or off) a stated length over the cap is refused on its
// headers, as before GAP-0516. A managed closed callout under auto still
// refuses an MCP request until a body has come (GAP-0146).
func TestGAP0516OverCapStillRefusedWhereBodiesAreSent(t *testing.T) {
	ctx := context.Background()
	big := bytes.Repeat([]byte("a"), (1<<20)+1)

	// The filter does send it (agent-substrate#3817): refused over the cap.
	h := newHarness(t, nil)
	r := bigMCPPost(h)
	v := h.eng.DecideHeaders(ctx, r)
	if v = h.eng.DecideBody(ctx, r, v, big); v.Allow || !v.BodyOverCap || v.Category != CategoryBodyUninspected {
		t.Fatalf("body over the cap arrived: %+v", v)
	}

	refused := map[string]func(*harness){
		"auto, a body seen": func(h *harness) { h.eng.body.arrived() },
		"on":                nil,
		"off":               nil,
	}
	for name, prep := range refused {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(c *Config, _ *Options) {
				switch name {
				case "on":
					c.BodyInspection = BodyOn
				case "off":
					c.BodyInspection = BodyOff
				}
			})
			if prep != nil {
				prep(h)
			}
			v := h.eng.DecideHeaders(ctx, bigMCPPost(h))
			if v.Allow || !v.BodyOverCap || v.Rule != whyOverCap || v.Category != CategoryBodyUninspected {
				t.Fatalf("%s: %+v (want refused over_cap)", name, v)
			}
			c := dial(t, h)
			s, cancel := open(t, c)
			defer cancel()
			r := exchange(t, s, mcpFramed(false, ":method", "POST", "content-type", "application/json",
				"content-length", strconv.Itoa(2000000)))
			if ir := r.GetImmediateResponse(); ir == nil || ir.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
				t.Fatalf("%s: %v (want 403)", name, r)
			}
		})
	}

	m := newHarness(t, func(c *Config, _ *Options) { c.Managed = true })
	if v := m.eng.DecideHeaders(ctx, bigMCPPost(m)); v.Allow || v.Rule != whyUnavailable {
		t.Fatalf("managed closed auto: %+v (want refused body_inspection_unavailable)", v)
	}
}
