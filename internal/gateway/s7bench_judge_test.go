// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package gateway

import (
	"context"
	"errors"
	"testing"
)

// stubJudgeProvider answers or fails on demand; it has no network.
type stubJudgeProvider struct {
	resp *ChatResponse
	err  error
}

func (s *stubJudgeProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	return s.resp, s.err
}

func (s *stubJudgeProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, cb func(StreamChunk)) (*ChatUsage, error) {
	return nil, errors.New("not used")
}

func judgeReq(system, user string, maxTok int) *ChatRequest {
	return &ChatRequest{Model: "m", MaxTokens: &maxTok, Messages: []ChatMessage{{Role: "system", Content: system}, {Role: "user", Content: user}}}
}

// Every judge request records the size it sent and its output cap, answered or not: a cut or failed call has no usage, and these are what the
// scorer prices it with (rel-1-0-10:GAP-0649).
func TestRecordingProviderRecordsRequestSizeOnEveryCall(t *testing.T) {
	rec := &s7RecordingProvider{calls: map[string][]S7JudgeCall{}, inflight: map[string]int{}}
	sid := "s7-benchfix3"

	// answered, with usage
	stop := "stop"
	rec.inner = &stubJudgeProvider{resp: &ChatResponse{Usage: &ChatUsage{PromptTokens: 700, CompletionTokens: 40},
		Choices: []ChatChoice{{Message: &ChatMessage{Role: "assistant", Content: `{"verdict":"safe"}`}, FinishReason: &stop}}}}
	if _, err := rec.ChatCompletion(ContextWithSessionID(context.Background(), sid), judgeReq("sys", "hello", 512)); err != nil {
		t.Fatal(err)
	}
	// cut: the caller's context ended; no usage comes back
	cctx, cancel := context.WithCancel(ContextWithSessionID(context.Background(), sid))
	cancel()
	rec.inner = &stubJudgeProvider{err: context.Canceled}
	if _, err := rec.ChatCompletion(cctx, judgeReq("sys", "a longer user turn", 1024)); err == nil {
		t.Fatal("want the stub error")
	}
	// failed on its own, context alive
	rec.inner = &stubJudgeProvider{err: errors.New("connection reset")}
	_, _ = rec.ChatCompletion(ContextWithSessionID(context.Background(), sid), judgeReq("", "x", 0))

	got := rec.calls[sid]
	if len(got) != 3 {
		t.Fatalf("want 3 recorded calls, got %d: %+v", len(got), got)
	}
	if got[0].ReqChars != len("sys")+len("hello") || got[0].MaxTok != 512 || got[0].InTokens != 700 || got[0].OutTokens != 40 {
		t.Fatalf("answered call: %+v", got[0])
	}
	if !got[1].Cancelled || got[1].Err == "" || got[1].InTokens != 0 || got[1].ReqChars != len("sys")+len("a longer user turn") || got[1].MaxTok != 1024 {
		t.Fatalf("cut call must keep its request size and no usage: %+v", got[1])
	}
	if got[2].Cancelled || got[2].Err == "" || got[2].ReqChars != 1 || got[2].MaxTok != 0 {
		t.Fatalf("failed call: %+v", got[2])
	}
}

func TestS7ReqCharsUsesRawContentWhenThereIsNoText(t *testing.T) {
	if n := s7ReqChars(nil); n != 0 {
		t.Fatalf("nil request: %d", n)
	}
	req := &ChatRequest{Messages: []ChatMessage{{Role: "user", RawContent: []byte(`[{"type":"text"}]`)}, {Role: "user", Content: "abc"}}}
	if n := s7ReqChars(req); n != len(`[{"type":"text"}]`)+3 {
		t.Fatalf("raw content not counted: %d", n)
	}
}
