// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"
	"testing"
)

// TestDisableAll_RuntimeOverride pins the contract that
// SetDisableAll(true) makes EVERY ForSink* helper return its raw
// input untouched. The persistent-sinks redaction guarantee
// documented in OBSERVABILITY.md is intentionally violated under
// this flag — operators flip it on for prompt-engineering
// debugging in single-tenant lab installs — so this test ensures
// the bypass reaches every redaction surface, not just the
// operator-facing display path that DEFENSECLAW_REVEAL_PII covers.
func TestDisableAll_RuntimeOverride(t *testing.T) {
	// Always restore the override state so the rest of the suite
	// keeps the default-redacting contract.
	t.Cleanup(func() { SetDisableAll(false) })

	// Sanity: default state (no env, no override) keeps redacting.
	if got := ForSinkString("user typed hello"); !strings.HasPrefix(got, "<redacted") {
		t.Fatalf("default ForSinkString must redact, got %q", got)
	}

	SetDisableAll(true)
	if !DisableAll() {
		t.Fatal("DisableAll() must return true after SetDisableAll(true)")
	}

	cases := []struct {
		name    string
		got     string
		want    string
		wantRaw bool // whether got should equal raw input
	}{
		{name: "ForSinkString", got: ForSinkString("user typed hello"), want: "user typed hello", wantRaw: true},
		{name: "ForSinkEntity", got: ForSinkEntity("alice@example.com"), want: "alice@example.com", wantRaw: true},
		{name: "ForSinkMessageContent", got: ForSinkMessageContent("paragraph of user prompt"), want: "paragraph of user prompt", wantRaw: true},
		{name: "ForSinkReason", got: ForSinkReason("SEC-OPENAI:sk-ant-1234567890abcdef"), want: "SEC-OPENAI:sk-ant-1234567890abcdef", wantRaw: true},
		{name: "ForSinkEvidence", got: ForSinkEvidence("paragraph match here", 8, 13), want: "paragraph match here", wantRaw: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("DisableAll bypass for %s: got %q, want %q", tc.name, tc.got, tc.want)
			}
		})
	}

	// Also check the Reveal-respecting variants — String/Entity/
	// MessageContent/Reason all funnel into ForSink* when Reveal()
	// is false, so the bypass must work transparently for them too.
	t.Setenv(revealEnvVar, "")
	if got := String("user typed hello"); got != "user typed hello" {
		t.Fatalf("String() with DisableAll on: got %q, want raw passthrough", got)
	}
	if got := Entity("alice@example.com"); got != "alice@example.com" {
		t.Fatalf("Entity() with DisableAll on: got %q, want raw passthrough", got)
	}
	if got := MessageContent("paragraph"); got != "paragraph" {
		t.Fatalf("MessageContent() with DisableAll on: got %q, want raw passthrough", got)
	}

	// Toggle off and confirm we re-enter the redacting path.
	SetDisableAll(false)
	if DisableAll() {
		t.Fatal("DisableAll() must return false after SetDisableAll(false)")
	}
	if got := ForSinkString("user typed hello"); !strings.HasPrefix(got, "<redacted") {
		t.Fatalf("ForSinkString must redact again after SetDisableAll(false): got %q", got)
	}
}

// TestDisableAll_EnvVar guards the second opt-out path: the
// DEFENSECLAW_DISABLE_REDACTION env var must produce the same
// bypass behavior as the runtime override. Environments set both
// (e.g. ``defenseclaw setup redaction off`` toggles config which
// becomes SetDisableAll, and a paranoid operator additionally
// exports the env var) and we want either to be sufficient.
func TestDisableAll_EnvVar(t *testing.T) {
	t.Cleanup(func() { SetDisableAll(false) })

	for _, val := range []string{"1", "true", "yes", "on", "TRUE", "  YES  "} {
		t.Run("on/"+val, func(t *testing.T) {
			t.Setenv(disableEnvVar, val)
			if !DisableAll() {
				t.Fatalf("DisableAll() must be true for env=%q", val)
			}
			if got := ForSinkMessageContent("user typed hello"); got != "user typed hello" {
				t.Fatalf("ForSinkMessageContent must passthrough for env=%q, got %q", val, got)
			}
		})
	}

	for _, val := range []string{"", "0", "false", "no", "off", "garbage"} {
		t.Run("off/"+val, func(t *testing.T) {
			t.Setenv(disableEnvVar, val)
			if DisableAll() {
				t.Fatalf("DisableAll() must be false for env=%q", val)
			}
			if got := ForSinkMessageContent("user typed hello"); !strings.HasPrefix(got, "<redacted") {
				t.Fatalf("ForSinkMessageContent must redact for env=%q, got %q", val, got)
			}
		})
	}
}

// TestDisableAll_PrecedenceOverReveal confirms that DisableAll
// short-circuits BEFORE the Reveal-flag check, so the strongest
// opt-out wins. Documented in the package doc; this test pins it
// so a future refactor can't accidentally let Reveal=false hide
// content that DisableAll=true should be passing through raw.
func TestDisableAll_PrecedenceOverReveal(t *testing.T) {
	t.Cleanup(func() { SetDisableAll(false) })
	t.Setenv(revealEnvVar, "")
	t.Setenv(disableEnvVar, "")

	SetDisableAll(true)
	// Reveal off, DisableAll on: raw passthrough still wins.
	if got := MessageContent("user prompt"); got != "user prompt" {
		t.Fatalf("DisableAll must take precedence over Reveal=false: got %q", got)
	}
	// Reveal off, DisableAll off: redacted as usual.
	SetDisableAll(false)
	if got := MessageContent("user prompt"); !strings.HasPrefix(got, "<redacted") {
		t.Fatalf("DisableAll=false, Reveal=false must redact: got %q", got)
	}
}
