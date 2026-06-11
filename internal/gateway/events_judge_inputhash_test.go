// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// TestEmitJudge_InputHashIsSHA256OfInputContent pins the contract that
// JudgePayload.InputHash is derived from JudgeEmitOpts.InputContent
// (the inspected judge input), NOT from the raw response body.
//
// Regression context (follow-up from PR #256 review): the
// original fix added the InputContent field but only updated
// the SQLite store unit test to set p.InputHash directly. None of the
// 16 production call sites in llm_judge.go populated InputContent and
// no test asserted the end-to-end digest. This test closes that loop:
// when InputContent="A" and RawResponse="B", InputHash must be
// sha256:<hex(sha256("A"))>.
func TestEmitJudge_InputHashIsSHA256OfInputContent(t *testing.T) {
	prevPersist := judgePersist()
	t.Cleanup(func() {
		// Restore whatever persistor the test process started with.
		// SetJudgePersistor takes nil to clear, so use a no-op when
		// prevPersist itself was nil.
		if prevPersist == nil {
			SetJudgePersistor(nil)
		} else {
			SetJudgePersistor(prevPersist)
		}
	})

	// Disable any judge store that other tests may have wired up so
	// our persist closure is the single sink.
	SetJudgeResponseStore(nil)
	t.Cleanup(func() { SetJudgeResponseStore(nil) })

	var captured gatewaylog.JudgePayload
	SetJudgePersistor(func(_ context.Context, p gatewaylog.JudgePayload, _ gatewaylog.Direction, _ JudgeEmitOpts) {
		captured = p
	})

	const input = "the inspected judge input text"
	const response = "the response body that must NOT drive the hash"
	emitJudge(
		context.Background(),
		"injection",
		"test-model",
		gatewaylog.DirectionPrompt,
		len(input),
		42,
		"allow",
		gatewaylog.SeverityInfo,
		"",
		response, // raw response body — non-empty so the persistor closure runs
		JudgeEmitOpts{InputContent: input},
	)

	want := sha256.Sum256([]byte(input))
	wantStr := "sha256:" + hex.EncodeToString(want[:])

	if captured.InputHash != wantStr {
		t.Fatalf("InputHash mismatch:\n  got  = %q\n  want = %q (sha256 of input, not response)",
			captured.InputHash, wantStr)
	}
	if captured.RawResponse != response {
		t.Fatalf("RawResponse should round-trip verbatim; got %q", captured.RawResponse)
	}
}

// TestEmitJudge_InputHashEmptyWhenNoInputContent pins that absent
// InputContent yields an empty digest (rather than e.g. silently
// hashing the response). This guards against future regressions
// where someone re-introduces a fallback to the response body.
func TestEmitJudge_InputHashEmptyWhenNoInputContent(t *testing.T) {
	prevPersist := judgePersist()
	t.Cleanup(func() {
		if prevPersist == nil {
			SetJudgePersistor(nil)
		} else {
			SetJudgePersistor(prevPersist)
		}
	})
	SetJudgeResponseStore(nil)
	t.Cleanup(func() { SetJudgeResponseStore(nil) })

	var captured gatewaylog.JudgePayload
	SetJudgePersistor(func(_ context.Context, p gatewaylog.JudgePayload, _ gatewaylog.Direction, _ JudgeEmitOpts) {
		captured = p
	})

	emitJudge(
		context.Background(),
		"injection",
		"m",
		gatewaylog.DirectionPrompt,
		1, 1, "allow", gatewaylog.SeverityInfo, "",
		"some-response",
		JudgeEmitOpts{}, // no InputContent
	)

	if captured.InputHash != "" {
		t.Fatalf("expected empty InputHash when InputContent is unset, got %q", captured.InputHash)
	}
}
