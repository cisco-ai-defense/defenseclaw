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
	"strconv"
	"strings"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

func mcpHeadersAs(atespace, name string, body []byte) *extprocv3.ProcessingRequest {
	return headersMsg(identityAttrs(atespace, name), false, ":method", "POST", ":authority", "mcp.example.com",
		":path", "/mcp", ":scheme", "https", "content-type", "application/json",
		"content-length", strconv.Itoa(len(body)))
}

// endRound sends qualifying headers and ends the stream without the body:
// a half-close, a cancel, or a response phase first (each one measured on
// cluster a4 and each one an actor can cause).
func endRound(t *testing.T, c extprocv3.ExternalProcessorClient, atespace, name, how string) {
	t.Helper()
	s, cancel := open(t, c)
	defer cancel()
	if r := exchange(t, s, mcpHeadersAs(atespace, name, mcpCall("x"))); r.GetModeOverride() == nil {
		t.Fatal("no override")
	}
	switch how {
	case signalCanceled:
		cancel()
		time.Sleep(20 * time.Millisecond)
	case signalResponse:
		resp := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{}}}
		if r := exchange(t, s, resp); r.GetResponseHeaders() == nil {
			t.Fatalf("got %v", r)
		}
		_ = s.CloseSend()
		_, _ = s.Recv()
	default:
		_ = s.CloseSend()
		if _, err := s.Recv(); err == nil {
			t.Fatal("stream did not end")
		}
	}
}

// TestBodyModeNeverSwitchedOffByMissingBodies is GAP-0045: no number of
// missing bodies, from any number of actors and however the stream ends,
// stops the callout from asking for bodies; each such request is an alert.
func TestBodyModeNeverSwitchedOffByMissingBodies(t *testing.T) {
	h := newHarness(t, nil)
	c := dial(t, h)
	n := 0
	for _, how := range []string{signalEOF, signalCanceled, signalResponse} {
		for i := 0; i < 4; i++ {
			endRound(t, c, "t"+strconv.Itoa(i), "c"+strconv.Itoa(i), how)
			n++
		}
	}
	if st := h.eng.BodyModeStatus(); st != "unknown" {
		t.Fatalf("body mode %s", st)
	}
	s, cancel := open(t, c)
	defer cancel()
	if r := exchange(t, s, mcpHeaders(mcpCall("x"))); r.GetModeOverride() == nil {
		t.Fatal("override no longer requested")
	}
	seen := map[string]bool{}
	for _, ev := range waitEvents(t, h.events, n) {
		if ev.BodyInspected || ev.Decision != "allow" || !ev.Alert {
			t.Fatalf("uninspected request event: %+v", ev)
		}
		for _, f := range ev.Findings {
			if strings.HasPrefix(f, "body_not_received:") {
				seen[strings.TrimPrefix(f, "body_not_received:")] = true
			}
		}
	}
	for _, how := range []string{signalEOF, signalCanceled, signalResponse} {
		if !seen[how] {
			t.Errorf("no body_not_received:%s event (%v)", how, seen)
		}
	}
}

func TestBodyModeStatus(t *testing.T) {
	b := newBodyMode(BodyAuto)
	if b.status() != "unknown" || !b.want() {
		t.Fatal(b.status())
	}
	b.arrived()
	if b.status() != "supported" {
		t.Fatal(b.status())
	}
	if off := newBodyMode(BodyOff); off.want() || off.status() != "off" {
		t.Fatal("off")
	}
	if on := newBodyMode(BodyOn); !on.want() {
		t.Fatal("on")
	}
}
