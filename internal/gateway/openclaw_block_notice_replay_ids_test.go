// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// OpenClaw replays a tool call to an Anthropic Messages, Chat Completions or
// Bedrock Converse provider with only the letters and digits of its id, cut to
// 40 characters. The block notice is tied to the result by that form of the
// recorded id; calls that share one form are ambiguous and show nothing.

func TestReplayToolCallIDKeepsLettersAndDigitsUpToForty(t *testing.T) {
	for _, tc := range []struct{ id, want string }{
		{"toolu_bdrk_019EmHn8vHTJCtXejb92RmFP", "toolubdrk019EmHn8vHTJCtXejb92RmFP"},
		{"toolubdrk019EmHn8vHTJCtXejb92RmFP", "toolubdrk019EmHn8vHTJCtXejb92RmFP"},
		{"call_a-b.c:1", "callabc1"},
		{"functions.exec:0", "functionsexec0"},
		{"___", "sanitizedtoolid"},
		{"", "sanitizedtoolid"},
		{"toolu_" + strings.Repeat("a1", 30), ("toolu" + strings.Repeat("a1", 30))[:40]},
	} {
		if got := replayToolCallID(tc.id); got != tc.want {
			t.Errorf("replayToolCallID(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

// The Anthropic Messages route with the id the model client really sends: the
// replayed tool_result carries the id without its underscores.
func TestGAP0644AnthropicResultCarriesTheReplayFormOfTheBlockedID(t *testing.T) {
	const blocked = "toolu_bdrk_019EmHn8vHTJCtXejb92RmFP"
	const replayed = "toolubdrk019EmHn8vHTJCtXejb92RmFP"
	line := openClawBlockNoticeLine("exec", []string{anthropicNoticeRule}, "matched: ssh authorized_keys write")
	for _, tc := range []struct {
		name         string
		stream, gzip bool
	}{
		{"sse", true, false},
		{"sse compressed upstream", true, true},
		{"json", false, false},
		{"json compressed upstream", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", blocked, noticeTestSession, []string{anthropicNoticeRule}, "matched: ssh authorized_keys write")
			out, _ := anthropicRoundTrip(t, replayed, tc.stream, tc.gzip)
			if tc.stream {
				if got, want := streamText(sseData(t, out), "anthropic"), line+"\n\n"+anthropicReplyText; got != want {
					t.Fatalf("streamed text = %q, want %q", got, want)
				}
			} else if !strings.Contains(out, `\n\n`+anthropicReplyText) || strings.Count(out, openClawBlockNoticeMark) != 1 {
				t.Fatalf("reply = %s", out)
			}
			if openClawBlockNoticesPending() {
				t.Fatal("the notice stayed pending after it was shown")
			}
			if again, _ := anthropicRoundTrip(t, replayed, tc.stream, tc.gzip); strings.Contains(again, openClawBlockNoticeMark) {
				t.Fatalf("the line was shown twice:\n%s", again)
			}
		})
	}
}

// Each adapter that carries the result id in a different field reads the same
// replay form, and an id cut to 40 characters still names its call.
func TestGAP0644ReplayFormOfTheBlockedIDIsTiedOnEveryAdapter(t *testing.T) {
	long := "call_" + strings.Repeat("Ab1", 20)
	for _, tc := range []struct {
		name, blocked, body string
	}{
		{"chat completions", "call_AbC123xyz", `{"messages":[{"role":"tool","tool_call_id":"callAbC123xyz","content":"x"}]}`},
		{"anthropic", "toolu_01AbC", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu01AbC"}]}]}`},
		{"bedrock converse", "tooluse_AbC-123", `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"tooluseAbC123"}}]}]}`},
		{"cut to forty", long, `{"messages":[{"role":"tool","tool_call_id":"` + replayToolCallID(long) + `"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", tc.blocked, noticeTestSession, []string{noticeTestRule}, "r")
			got := takeOpenClawBlockNotices([]byte(tc.body), noticeTestSession)
			if len(got) != 1 {
				t.Fatalf("taken %d notices, want 1", len(got))
			}
		})
	}
}

// Calls whose ids have one replay form cannot be told apart by a result, so the
// block shows nothing and is consumed, whichever came first, and an allowed
// call of the same form does the same. Another session, and a different id,
// never take the block.
func TestGAP0644CallsSharingAReplayFormShowNothing(t *testing.T) {
	const result = `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolubdrk01Ab"}]}]}`
	for _, tc := range []struct {
		name string
		prep func()
	}{
		{"two blocks", func() {
			rememberOpenClawBlockNotice("exec", "toolu_bdrk_01Ab", noticeTestSession, []string{noticeTestRule}, "r")
			rememberOpenClawBlockNotice("exec", "toolu-bdrk-01Ab", noticeTestSession, []string{noticeTestRule}, "r")
		}},
		{"allowed call first", func() {
			observeOpenClawToolCall("toolu-bdrk-01Ab")
			rememberOpenClawBlockNotice("exec", "toolu_bdrk_01Ab", noticeTestSession, []string{noticeTestRule}, "r")
		}},
		{"allowed call after", func() {
			rememberOpenClawBlockNotice("exec", "toolu_bdrk_01Ab", noticeTestSession, []string{noticeTestRule}, "r")
			observeOpenClawToolCall("toolu-bdrk-01Ab")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			tc.prep()
			if got := takeOpenClawBlockNotices([]byte(result), noticeTestSession); len(got) != 0 {
				t.Fatalf("an ambiguous block was shown: %v", got)
			}
		})
	}
	t.Run("other session and other id", func(t *testing.T) {
		resetOpenClawBlockNotices(t)
		rememberOpenClawBlockNotice("exec", "toolu_bdrk_01Ab", "other-session", []string{noticeTestRule}, "r")
		if got := takeOpenClawBlockNotices([]byte(result), noticeTestSession); len(got) != 0 {
			t.Fatalf("another session took the block: %v", got)
		}
		resetOpenClawBlockNotices(t)
		rememberOpenClawBlockNotice("exec", "toolu_bdrk_01Ac", noticeTestSession, []string{noticeTestRule}, "r")
		if got := takeOpenClawBlockNotices([]byte(result), noticeTestSession); len(got) != 0 || !openClawBlockNoticesPending() {
			t.Fatalf("another id took the block: %v", got)
		}
	})
}
