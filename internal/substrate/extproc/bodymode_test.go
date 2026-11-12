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

func waitStatus(t *testing.T, e *Engine, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for e.BodyModeStatus() != want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := e.BodyModeStatus(); st != want {
		t.Fatalf("body mode %s, want %s", st, want)
	}
}

// stockRound sends qualifying headers and ends the stream without a body:
// a clean half-close, or a cancel (what stock v1.0.0 and an aborting client
// both do).
func stockRound(t *testing.T, c extprocv3.ExternalProcessorClient, atespace, name string, cancelIt bool) {
	t.Helper()
	s, cancel := open(t, c)
	defer cancel()
	if r := exchange(t, s, mcpHeadersAs(atespace, name, mcpCall("x"))); r.GetModeOverride() == nil {
		t.Fatal("no override")
	}
	if cancelIt {
		cancel()
		time.Sleep(20 * time.Millisecond)
		return
	}
	_ = s.CloseSend()
	if _, err := s.Recv(); err == nil {
		t.Fatal("stream did not end")
	}
}

// TestBodyModeDetectionStock: clean ends without a body from two actors
// mark the replica unsupported; after that no override is requested.
func TestBodyModeDetectionStock(t *testing.T) {
	h := newHarness(t, nil)
	c := dial(t, h)
	stockRound(t, c, "t1", "c1", false)
	stockRound(t, c, "t1", "c1", false)
	stockRound(t, c, "t2", "c2", false)
	waitStatus(t, h.eng, "unsupported")
	s, cancel := open(t, c)
	defer cancel()
	if r := exchange(t, s, mcpHeaders(mcpCall("x"))); r.GetModeOverride() != nil {
		t.Fatal("override still requested after detection")
	}
	evs := waitEvents(t, h.events, bodyMissLimit)
	if evs[0].BodyInspected || evs[0].Decision != "allow" || !evs[0].Alert ||
		!strings.Contains(strings.Join(evs[0].Findings, ","), "body_not_received:eof") {
		t.Fatalf("uninspected request event: %+v", evs[0])
	}
}

// TestBodyModeDetectionIgnoresOneActorAndCancels is GAP-0045: aborted
// streams and any number of clean misses from one actor never switch body
// inspection off for the replica.
func TestBodyModeDetectionIgnoresOneActorAndCancels(t *testing.T) {
	h := newHarness(t, nil)
	c := dial(t, h)
	for i := 0; i < 2*bodyMissLimit; i++ {
		stockRound(t, c, "t1", "c1", true)
		stockRound(t, c, "t1", "c1", false)
	}
	// Cancels from a second actor do not count either.
	for i := 0; i < bodyMissLimit; i++ {
		stockRound(t, c, "t2", "c2", true)
	}
	time.Sleep(50 * time.Millisecond)
	if st := h.eng.BodyModeStatus(); st != "unknown" {
		t.Fatalf("body mode %s after one actor's misses and cancels", st)
	}
	s, cancel := open(t, c)
	defer cancel()
	if r := exchange(t, s, mcpHeaders(mcpCall("x"))); r.GetModeOverride() == nil {
		t.Fatal("override no longer requested")
	}
}

// A response phase before the body is proof the filter ignored the
// override; a body marks it supported, and misses never undo that.
func TestBodyModeResponseSignalAndSticky(t *testing.T) {
	b := newBodyMode(BodyAuto, time.Now)
	b.missed("a/1", signalCanceled)
	b.missed("a/1", signalError)
	if b.status() != "unknown" {
		t.Fatal(b.status())
	}
	b.missed("a/1", signalResponse)
	if b.status() != "unsupported" || b.want() {
		t.Fatal(b.status())
	}
	b = newBodyMode(BodyAuto, time.Now)
	b.arrived()
	for i := 0; i < 10; i++ {
		b.missed("x/"+strconv.Itoa(i), signalEOF)
		b.missed("x/"+strconv.Itoa(i), signalResponse)
	}
	if b.status() != "supported" {
		t.Fatal(b.status())
	}
	// Pinned on: detection never switches it off.
	b = newBodyMode(BodyOn, time.Now)
	b.missed("a/1", signalResponse)
	if !b.want() {
		t.Fatal("pinned on stopped asking")
	}
}
