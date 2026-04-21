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
	"context"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

func TestEmitJudge_PersistsUnredactedRawBeforeFanoutScrub(t *testing.T) {
	capture := withCapturedEvents(t)

	// Install a persistor that records the payload it was called
	// with. emitJudge runs the persistor on the original payload
	// (before emitEvent shallow-copies + redacts), so the SQLite
	// sink receives the un-redacted body while the fanout / JSONL
	// sees the scrubbed form.
	var (
		persistedMu        sync.Mutex
		persistedRaw       string
		persistedDirection gatewaylog.Direction
		persistedInvoked   int
	)
	SetJudgePersistor(func(_ context.Context, p gatewaylog.JudgePayload, dir gatewaylog.Direction, _ JudgeEmitOpts) {
		persistedMu.Lock()
		defer persistedMu.Unlock()
		persistedRaw = p.RawResponse
		persistedDirection = dir
		persistedInvoked++
	})
	t.Cleanup(func() { SetJudgePersistor(nil) })

	raw := `{"verdict":"block","reason":"email found: victim@example.com"}`
	emitJudge(t.Context(), "pii", "gpt-4", gatewaylog.DirectionPrompt, 128, 42, "block",
		gatewaylog.SeverityHigh, "", raw, JudgeEmitOpts{})

	persistedMu.Lock()
	gotRaw := persistedRaw
	gotCalls := persistedInvoked
	gotDir := persistedDirection
	persistedMu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("persistor called %d times want 1", gotCalls)
	}
	if gotRaw != raw {
		t.Fatalf("persistor got redacted raw=%q want unredacted=%q", gotRaw, raw)
	}
	// Regression: direction must flow through the persistor; a
	// prior revision wrote empty strings to SQLite because the
	// hook signature dropped this field.
	if gotDir != gatewaylog.DirectionPrompt {
		t.Fatalf("persistor got direction=%q want %q", gotDir, gatewaylog.DirectionPrompt)
	}

	// Sink-side payload must have been scrubbed by emitEvent.
	if len(*capture) != 1 {
		t.Fatalf("captured %d events want 1", len(*capture))
	}
	jp := (*capture)[0].Judge
	if jp == nil {
		t.Fatal("judge payload missing from captured event")
	}
	if jp.RawResponse == raw {
		t.Fatalf("fanout saw un-redacted raw — redaction layer bypassed")
	}
}

func TestEmitJudge_EmptyRawDoesNotCallPersistor(t *testing.T) {
	_ = withCapturedEvents(t)

	var called int
	SetJudgePersistor(func(_ context.Context, _ gatewaylog.JudgePayload, _ gatewaylog.Direction, _ JudgeEmitOpts) { called++ })
	t.Cleanup(func() { SetJudgePersistor(nil) })

	emitJudge(t.Context(), "injection", "gpt-4", gatewaylog.DirectionPrompt, 0, 1, "allow",
		gatewaylog.SeverityInfo, "", "", JudgeEmitOpts{})
	if called != 0 {
		t.Fatalf("persistor called %d times on empty raw (retention no-op path)", called)
	}
}

func TestEmitJudge_NilPersistorSafe(t *testing.T) {
	_ = withCapturedEvents(t)
	SetJudgePersistor(nil)
	// Must not panic.
	emitJudge(t.Context(), "pii", "gpt-4", gatewaylog.DirectionPrompt, 10, 1, "allow",
		gatewaylog.SeverityInfo, "", "raw body", JudgeEmitOpts{})
}
