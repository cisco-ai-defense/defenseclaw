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
	"strconv"
	"strings"
	"testing"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/proto"
)

func mcpFramed(eos bool, kv ...string) *extprocv3.ProcessingRequest {
	base := []string{":authority", "mcp.example.com", ":path", "/mcp", ":scheme", "https"}
	return headersMsg(identityAttrs("t1", "c1"), eos, append(base, kv...)...)
}

// TestBodyFramingCannotSkipInspection is GAP-0044: on an MCP host the actor
// cannot choose a framing that skips body inspection. Every request with a
// body is inspected (any method, content type or missing length), or
// refused in closed mode when it can't be (over the cap, streaming types).
func TestBodyFramingCannotSkipInspection(t *testing.T) {
	body := mcpCall("delete_everything")
	inspect := []struct {
		name string
		msg  *extprocv3.ProcessingRequest
	}{
		{"chunked, no length", mcpFramed(false, ":method", "POST", "content-type", "application/json", "transfer-encoding", "chunked")},
		{"text/plain", mcpFramed(false, ":method", "POST", "content-type", "text/plain", "content-length", strconv.Itoa(len(body)))},
		{"no content type", mcpFramed(false, ":method", "POST", "content-length", strconv.Itoa(len(body)))},
		{"form encoded", mcpFramed(false, ":method", "POST", "content-type", "application/x-www-form-urlencoded")},
		{"GET with a body", mcpFramed(false, ":method", "GET", "content-type", "application/json")},
		{"DELETE with a body", mcpFramed(false, ":method", "DELETE", "content-type", "application/json")},
		{"content-length 0 but a body follows", mcpFramed(false, ":method", "POST", "content-type", "application/json", "content-length", "0")},
	}
	h := newHarness(t, nil)
	h.judge.block = true
	c := dial(t, h)
	for _, tc := range inspect {
		t.Run(tc.name, func(t *testing.T) {
			s, cancel := open(t, c)
			defer cancel()
			r := exchange(t, s, tc.msg)
			if !proto.Equal(r.GetModeOverride(), overrideMode()) {
				t.Fatalf("no body inspection: %v", r)
			}
			r = exchange(t, s, bodyMsg(body))
			if ir := r.GetImmediateResponse(); ir == nil || !bytes.Contains(ir.GetBody(), []byte(CategoryMCPToolBlocked)) {
				t.Fatalf("tool call not judged: %v", r)
			}
		})
	}

	refuse := []struct {
		name, why string
		msg       *extprocv3.ProcessingRequest
	}{
		{"over the cap", whyOverCap, mcpFramed(false, ":method", "POST", "content-type", "application/json", "content-length", strconv.Itoa(2<<20))},
		{"event-stream body", whyStreaming, mcpFramed(false, ":method", "POST", "content-type", "text/event-stream")},
		{"multipart body", whyStreaming, mcpFramed(false, ":method", "POST", "content-type", "multipart/form-data; boundary=x")},
		{"grpc on a listed host", whyStreaming, headersMsg(identityAttrs("t1", "c1"), false, ":method", "POST",
			":authority", "upload.example.org", ":path", "/svc/M", "content-type", "application/grpc")},
	}
	for _, tc := range refuse {
		t.Run("closed "+tc.name, func(t *testing.T) {
			s, cancel := open(t, c)
			defer cancel()
			r := exchange(t, s, tc.msg)
			ir := r.GetImmediateResponse()
			if ir == nil || ir.GetStatus().GetCode() != typev3.StatusCode_Forbidden || !bytes.Contains(ir.GetBody(), []byte(CategoryBodyUninspected)) {
				t.Fatalf("not refused: %v", r)
			}
		})
	}
	open_ := newHarness(t, func(c *Config, _ *Options) { c.FailureMode = FailureOpen })
	for _, tc := range refuse {
		t.Run("open "+tc.name, func(t *testing.T) {
			r := open_.eng.requestFrom(tc.msg, tc.msg.GetRequestHeaders())
			v := open_.eng.DecideHeaders(context.Background(), r)
			if !v.Allow || !v.Alert || v.WantBody || !strings.Contains(strings.Join(v.Findings, ","), "body_not_inspected:"+tc.why) {
				t.Fatalf("open mode: %+v", v)
			}
		})
	}
}

// Never buffered and never refused: no body, the model path, other hosts.
func TestBodyModeNeverForBodylessOrModelOrOtherHosts(t *testing.T) {
	h := newHarness(t, nil)
	cases := []*extprocv3.ProcessingRequest{
		mcpFramed(true, ":method", "GET", "accept", "text/event-stream"),
		mcpFramed(true, ":method", "POST", "content-type", "application/json", "content-length", "0"),
		headersMsg(identityAttrs("t1", "c1"), false, ":method", "POST",
			":authority", "defenseclaw-actor.defenseclaw-system.svc", ":path", "/llm/bedrock/model/x/invoke-with-response-stream",
			"content-type", "application/json", "content-length", "100"),
		headersMsg(identityAttrs("t1", "c1"), false, ":method", "POST", ":authority", "example.com",
			":path", "/", "content-type", "text/event-stream"),
	}
	c := dial(t, h)
	for i, m := range cases {
		s, cancel := open(t, c)
		r := exchange(t, s, m)
		cancel()
		if r.GetModeOverride() != nil || r.GetRequestHeaders() == nil {
			t.Fatalf("case %d: %v", i, r)
		}
	}
}

// A body sent without a length that turns out larger than the cap.
func TestDecideBodyOverCapByFailureMode(t *testing.T) {
	big := bytes.Repeat([]byte("a"), (1<<20)+1)
	r := req("eng-web", "POST", "mcp.example.com", "/mcp")
	closed := newHarness(t, nil)
	if v := closed.eng.DecideBody(context.Background(), r, Verdict{Allow: true}, big); v.Allow || v.Category != CategoryBodyUninspected {
		t.Fatalf("closed: %+v", v)
	}
	open_ := newHarness(t, func(c *Config, _ *Options) { c.FailureMode = FailureOpen })
	if v := open_.eng.DecideBody(context.Background(), r, Verdict{Allow: true}, big); !v.Allow || !v.Alert || !v.BodyOverCap || v.BodyInspected {
		t.Fatalf("open: %+v", v)
	}
}

// With body_inspection off an MCP request is never silent: it is recorded.
func TestBodyModeUnavailableIsRecorded(t *testing.T) {
	off := newHarness(t, func(c *Config, _ *Options) { c.BodyInspection = BodyOff })
	r := off.eng.requestFrom(mcpHeaders(mcpCall("x")), mcpHeaders(mcpCall("x")).GetRequestHeaders())
	if v := off.eng.DecideHeaders(context.Background(), r); !v.Allow || v.WantBody || !strings.Contains(strings.Join(v.Findings, ","), whyInspectOff) {
		t.Fatalf("off: %+v", v)
	}
}
