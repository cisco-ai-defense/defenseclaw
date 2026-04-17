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
		persistedMu      sync.Mutex
		persistedRaw     string
		persistedInvoked int
	)
	SetJudgePersistor(func(p gatewaylog.JudgePayload) {
		persistedMu.Lock()
		defer persistedMu.Unlock()
		persistedRaw = p.RawResponse
		persistedInvoked++
	})
	t.Cleanup(func() { SetJudgePersistor(nil) })

	raw := `{"verdict":"block","reason":"email found: victim@example.com"}`
	emitJudge("pii", "gpt-4", gatewaylog.DirectionPrompt, 128, 42, "block",
		gatewaylog.SeverityHigh, "", raw)

	persistedMu.Lock()
	gotRaw := persistedRaw
	gotCalls := persistedInvoked
	persistedMu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("persistor called %d times want 1", gotCalls)
	}
	if gotRaw != raw {
		t.Fatalf("persistor got redacted raw=%q want unredacted=%q", gotRaw, raw)
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
	SetJudgePersistor(func(p gatewaylog.JudgePayload) { called++ })
	t.Cleanup(func() { SetJudgePersistor(nil) })

	emitJudge("injection", "gpt-4", gatewaylog.DirectionPrompt, 0, 1, "allow",
		gatewaylog.SeverityInfo, "", "")
	if called != 0 {
		t.Fatalf("persistor called %d times on empty raw (retention no-op path)", called)
	}
}

func TestEmitJudge_NilPersistorSafe(t *testing.T) {
	_ = withCapturedEvents(t)
	SetJudgePersistor(nil)
	// Must not panic.
	emitJudge("pii", "gpt-4", gatewaylog.DirectionPrompt, 10, 1, "allow",
		gatewaylog.SeverityInfo, "", "raw body")
}
