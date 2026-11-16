// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// The strict replay form of a tool call id (replayToolCallID) is what OpenClaw
// sends to the Chat Completions, Anthropic Messages and Bedrock Converse
// providers. The Responses route keeps the id as recorded, so the replay form,
// and the tie it creates between calls, belong to the first three only.

func responsesNoticeRoute(t *testing.T, body string) string {
	t.Helper()
	out, _ := serveNoticeWith(t, noticeServe{path: "/openai/v1/responses", reqBody: body, ctype: "text/event-stream", respBody: responsesReasoningStream()})
	return out
}

// A Responses call whose id is "<call>|<item>" is not claimed by another
// inspected call whose call id happens to equal the replay form of the full id.
func TestGAP0644ResponsesOtherCallCannotClaimTheReplayFormOfAFullID(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_ab|fc_1", noticeTestSession, []string{noticeTestRule}, "r")
	observeOpenClawToolCall("callabfc1|fc_2")
	other := responsesBody("function_call_output", "callabfc1", [2]string{"callabfc1", "fc_2"})
	if out := responsesNoticeRoute(t, other); strings.Contains(out, openClawBlockNoticeMark) || !openClawBlockNoticesPending() {
		t.Fatalf("an unrelated Responses result took the block: out=%q pending=%v", out, openClawBlockNoticesPending())
	}
	own := responsesBody("function_call_output", "call_ab", [2]string{"call_ab", "fc_1"})
	out := responsesNoticeRoute(t, own)
	if !strings.Contains(out, openClawBlockNoticeMark) || openClawBlockNoticesPending() {
		t.Fatalf("the blocked Responses result lost its line: out=%q pending=%v", out, openClawBlockNoticesPending())
	}
}

// Responses keeps two ids that differ only by punctuation distinct, and its
// result carries the exact blocked id, so the line is shown. The same two ids
// on a strict-replay adapter are one id to the model and show nothing.
func TestGAP0644DistinctIDsOfOneReplayFormAreTiedOnlyWhereTheyReplayAlike(t *testing.T) {
	prep := func() {
		resetOpenClawBlockNotices(t)
		observeOpenClawToolCall("call_ab")
		rememberOpenClawBlockNotice("exec", "call_a-b", noticeTestSession, []string{noticeTestRule}, "r")
	}
	t.Run("responses shows the exact blocked id", func(t *testing.T) {
		prep()
		out := responsesNoticeRoute(t, responsesBody("function_call_output", "call_a-b", [2]string{"call_a-b", "fc_1"}))
		if !strings.Contains(out, openClawBlockNoticeMark) || openClawBlockNoticesPending() {
			t.Fatalf("distinct exact Responses id was suppressed: out=%q pending=%v", out, openClawBlockNoticesPending())
		}
	})
	t.Run("responses result of the other id takes nothing", func(t *testing.T) {
		prep()
		out := responsesNoticeRoute(t, responsesBody("function_call_output", "call_ab", [2]string{"call_ab", "fc_1"}))
		if strings.Contains(out, openClawBlockNoticeMark) || !openClawBlockNoticesPending() {
			t.Fatalf("the other call id took the block: out=%q pending=%v", out, openClawBlockNoticesPending())
		}
	})
	for _, tc := range []struct{ name, body string }{
		{"chat", `{"messages":[{"role":"tool","tool_call_id":"callab","content":"x"}]}`},
		{"anthropic", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"callab"}]}]}`},
		{"converse", `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"callab"}}]}]}`},
	} {
		t.Run(tc.name+" shows nothing and consumes the block", func(t *testing.T) {
			prep()
			if got := takeOpenClawBlockNotices([]byte(tc.body), noticeTestSession); len(got) != 0 || openClawBlockNoticesPending() {
				t.Fatalf("a replay-ambiguous block was shown or left pending: taken=%d pending=%v", len(got), openClawBlockNoticesPending())
			}
		})
	}
}
