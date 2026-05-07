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

package gatewaylog

import (
	"strings"
	"testing"
)

// TestComputePayloadHMAC_DeterministicForSameInput locks the canonical
// JSON contract: re-marshaling the same payload with the same key
// must produce the same digest, even when Go's map iteration order
// differs across calls.
func TestComputePayloadHMAC_DeterministicForSameInput(t *testing.T) {
	resetTelemetryHMACSeedForTest()
	SetTelemetryHMACSeed([]byte("test-seed-32-bytes-long-padding!"))

	p := EgressPayload{
		TargetHost: "api.openai.com",
		TargetPath: "/v1/chat/completions",
		BodyShape:  "messages",
		Branch:     "known",
		Decision:   "allow",
		Source:     "go",
	}
	d1 := ComputePayloadHMAC(p)
	d2 := ComputePayloadHMAC(p)
	if d1 == "" {
		t.Fatal("expected non-empty digest after seeding")
	}
	if d1 != d2 {
		t.Fatalf("digest not deterministic: %q vs %q", d1, d2)
	}
	if len(d1) != 64 {
		t.Fatalf("expected 64-hex-char digest (HMAC-SHA256), got len=%d", len(d1))
	}
}

// TestComputePayloadHMAC_DiffersForDifferentInput is the trivial
// integrity property — a single field change yields a different MAC.
func TestComputePayloadHMAC_DiffersForDifferentInput(t *testing.T) {
	resetTelemetryHMACSeedForTest()
	SetTelemetryHMACSeed([]byte("test-seed-32-bytes-long-padding!"))

	a := EgressPayload{TargetHost: "a.example.com", Branch: "known", Decision: "allow", Source: "go"}
	b := EgressPayload{TargetHost: "b.example.com", Branch: "known", Decision: "allow", Source: "go"}
	if ComputePayloadHMAC(a) == ComputePayloadHMAC(b) {
		t.Fatal("digests must differ for different payloads")
	}
}

// TestComputePayloadHMAC_NoOpWithoutSeed locks the boot-ordering
// fallback: if SetTelemetryHMACSeed has not been called, the
// computation returns "" rather than panicking.
func TestComputePayloadHMAC_NoOpWithoutSeed(t *testing.T) {
	resetTelemetryHMACSeedForTest()
	p := EgressPayload{TargetHost: "x.example.com", Branch: "known", Decision: "allow", Source: "go"}
	d := ComputePayloadHMAC(p)
	if d != "" {
		t.Fatalf("expected empty digest when seed unset, got %q", d)
	}
}

// TestVerifyPayloadHMAC_RoundTrip is the audit-side property: a
// digest produced by ComputePayloadHMAC must verify against the same
// payload + key.
func TestVerifyPayloadHMAC_RoundTrip(t *testing.T) {
	resetTelemetryHMACSeedForTest()
	SetTelemetryHMACSeed([]byte("test-seed-32-bytes-long-padding!"))

	p := VerdictPayload{Stage: StageRegex, Action: "block", Reason: "redacted reason"}
	d := ComputePayloadHMAC(p)
	if err := VerifyPayloadHMAC(p, d); err != nil {
		t.Fatalf("verify round-trip failed: %v", err)
	}
	// Tamper.
	p.Reason = "different reason"
	if err := VerifyPayloadHMAC(p, d); err == nil {
		t.Fatal("verify must fail on tampered payload")
	} else if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected mismatch error, got: %v", err)
	}
}

// TestStampPayloadHMAC_PicksRightPayload locks the dispatcher: the
// stamper must compute the digest over whichever single payload field
// is non-nil.
func TestStampPayloadHMAC_PicksRightPayload(t *testing.T) {
	resetTelemetryHMACSeedForTest()
	SetTelemetryHMACSeed([]byte("test-seed-32-bytes-long-padding!"))

	verdict := &VerdictPayload{Stage: StageRegex, Action: "block"}
	e := Event{
		EventType: EventVerdict,
		Verdict:   verdict,
	}
	e.StampPayloadHMAC()
	if e.PayloadHMAC == "" {
		t.Fatal("expected stamped HMAC for verdict payload")
	}
	expected := ComputePayloadHMAC(verdict)
	if e.PayloadHMAC != expected {
		t.Fatalf("StampPayloadHMAC stamped wrong digest: got %q want %q", e.PayloadHMAC, expected)
	}
}

// TestStampPayloadHMAC_NoOpWhenAllNil — envelope-only events skip
// stamping.
func TestStampPayloadHMAC_NoOpWhenAllNil(t *testing.T) {
	resetTelemetryHMACSeedForTest()
	SetTelemetryHMACSeed([]byte("test-seed-32-bytes-long-padding!"))

	e := Event{EventType: EventLifecycle}
	e.StampPayloadHMAC()
	if e.PayloadHMAC != "" {
		t.Fatalf("expected empty HMAC when all payloads nil, got %q", e.PayloadHMAC)
	}
}

// TestSetTelemetryHMACSeed_OncePerProcess confirms the sync.Once
// guard: a second call with a different seed silently no-ops, so
// downstream callers can't be surprised by a key flip mid-run.
func TestSetTelemetryHMACSeed_OncePerProcess(t *testing.T) {
	resetTelemetryHMACSeedForTest()
	SetTelemetryHMACSeed([]byte("seed-A-32-bytes-padding-12345678"))
	first := ComputePayloadHMAC(EgressPayload{TargetHost: "z.test", Branch: "known", Decision: "allow", Source: "go"})

	SetTelemetryHMACSeed([]byte("seed-B-32-bytes-padding-12345678"))
	second := ComputePayloadHMAC(EgressPayload{TargetHost: "z.test", Branch: "known", Decision: "allow", Source: "go"})

	if first != second {
		t.Fatalf("second SetTelemetryHMACSeed call should have been a no-op, but digests differ: %q vs %q", first, second)
	}
}
