// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// These tests pin the opt-in semantics of Phase 2.3 (retain judge raw
// bodies). The hot path is `judgeRawForEmit`, which MUST be default-off
// and ONLY return the truncated raw body when one of two controls is
// explicitly enabled:
//
//  1. DEFENSECLAW_JUDGE_TRACE=1 (ephemeral, session-only)
//  2. guardrail.retain_judge_bodies = true (durable, via SetRetainJudgeBodies)
//
// A regression here would silently persist model-echoed PII into
// gateway.jsonl, the OTel logs pipeline, and every configured audit
// sink — which is exactly the failure mode the review called out.

const judgePayload = "The user prompt contains phone 555-123-4567 and email a@b.com"

func restoreRetainJudgeBodies(t *testing.T) {
	t.Helper()
	prev := retainJudgeBodies.Load()
	t.Cleanup(func() { retainJudgeBodies.Store(prev) })
}

func TestJudgeRawForEmit_DefaultOffReturnsEmpty(t *testing.T) {
	restoreRetainJudgeBodies(t)
	// Ensure neither control is on. t.Setenv restores automatically.
	t.Setenv("DEFENSECLAW_JUDGE_TRACE", "")
	retainJudgeBodies.Store(false)

	if got := judgeRawForEmit(judgePayload); got != "" {
		t.Fatalf("default-off leak: judgeRawForEmit=%q (must be empty)", got)
	}
}

func TestJudgeRawForEmit_EnvTraceEnables(t *testing.T) {
	restoreRetainJudgeBodies(t)
	retainJudgeBodies.Store(false)

	for _, v := range []string{"1", "true", "yes", "on", "TRUE", "Yes", " 1 "} {
		t.Run("env="+v, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_JUDGE_TRACE", v)
			if got := judgeRawForEmit(judgePayload); !strings.Contains(got, "phone") {
				t.Fatalf("env %q did not enable retention: %q", v, got)
			}
		})
	}
}

func TestJudgeRawForEmit_EnvFalsyKeepsOff(t *testing.T) {
	restoreRetainJudgeBodies(t)
	retainJudgeBodies.Store(false)
	for _, v := range []string{"0", "false", "no", "off", ""} {
		t.Run("env="+v, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_JUDGE_TRACE", v)
			if got := judgeRawForEmit(judgePayload); got != "" {
				t.Fatalf("falsy env %q leaked body: %q", v, got)
			}
		})
	}
}

func TestSetRetainJudgeBodies_EnablesRetention(t *testing.T) {
	restoreRetainJudgeBodies(t)
	t.Setenv("DEFENSECLAW_JUDGE_TRACE", "")

	SetRetainJudgeBodies(true)
	if got := judgeRawForEmit(judgePayload); !strings.Contains(got, "phone") {
		t.Fatalf("SetRetainJudgeBodies(true) did not enable retention: %q", got)
	}

	// Disabling must take effect immediately — operators flip this on a
	// config reload to stop capturing sensitive payloads.
	SetRetainJudgeBodies(false)
	if got := judgeRawForEmit(judgePayload); got != "" {
		t.Fatalf("SetRetainJudgeBodies(false) did not stop retention: %q", got)
	}
}

func TestJudgeRawForEmit_TruncatesLongBodies(t *testing.T) {
	restoreRetainJudgeBodies(t)
	SetRetainJudgeBodies(true)
	// truncateJudgeLog caps at 500 in judgeRawForEmit.
	long := strings.Repeat("a", 2000)
	out := judgeRawForEmit(long)
	if len(out) > 600 { // allow truncation marker overhead
		t.Fatalf("long body not truncated: len=%d", len(out))
	}
	if !strings.HasPrefix(out, "aaaa") {
		t.Fatalf("truncated output missing expected prefix: %q", out[:20])
	}
}

func TestJudgeLogTrace_DefaultsFalse(t *testing.T) {
	t.Setenv("DEFENSECLAW_JUDGE_TRACE", "")
	if judgeLogTrace() {
		t.Fatal("judgeLogTrace must default to false when env unset")
	}
}

func TestJudgeLogTrace_UnknownValueIsFalse(t *testing.T) {
	// Unknown strings (including numeric "2") must not enable tracing —
	// operators occasionally set this to the wrong value and we don't
	// want silent PII retention as a consequence.
	for _, v := range []string{"2", "enabled", "maybe", "Y"} {
		t.Setenv("DEFENSECLAW_JUDGE_TRACE", v)
		if judgeLogTrace() {
			t.Fatalf("judgeLogTrace(%q)=true; must be false for unknown values", v)
		}
	}
}
