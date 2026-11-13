// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package gateway

// Benchmark-only recorder for the cascade runs: it wraps the hook judge's
// provider so every LLM judge request the real hook path makes is timed and
// its answer read with the product's own parser, per session. Nothing here
// changes a verdict; the hook answer is still the product's.

import (
	"context"
	"sync"
	"time"
)

// S7JudgeCall is one LLM judge request made by the hook path.
type S7JudgeCall struct {
	LatencyMs  int64    `json:"latency_ms"`
	Err        string   `json:"err,omitempty"`
	Parsed     bool     `json:"parsed"`
	Action     string   `json:"action,omitempty"`
	Severity   string   `json:"sev,omitempty"`
	Findings   []string `json:"findings,omitempty"`
	InTokens   int64    `json:"in_tok,omitempty"`
	OutTokens  int64    `json:"out_tok,omitempty"`
	Cancelled  bool     `json:"cancelled,omitempty"`
	RespLength int      `json:"resp_len,omitempty"`
}

type s7RecordingProvider struct {
	inner    LLMProvider
	mu       sync.Mutex
	calls    map[string][]S7JudgeCall
	inflight map[string]int
}

func (p *s7RecordingProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	sid := SessionIDFromContext(ctx)
	p.mu.Lock()
	p.inflight[sid]++
	p.mu.Unlock()
	t0 := time.Now()
	resp, err := p.inner.ChatCompletion(ctx, req)
	c := S7JudgeCall{LatencyMs: time.Since(t0).Milliseconds()}
	if err != nil {
		c.Err = err.Error()
		if len(c.Err) > 200 {
			c.Err = c.Err[:200]
		}
		c.Cancelled = ctx.Err() != nil
	} else if resp != nil {
		if resp.Usage != nil {
			c.InTokens, c.OutTokens = resp.Usage.PromptTokens, resp.Usage.CompletionTokens
		}
		if len(resp.Choices) > 0 && resp.Choices[0].Message != nil {
			raw := resp.Choices[0].Message.Content
			c.RespLength = len(raw)
			if parsed := parseJudgeJSON(raw); parsed != nil {
				v := toolInjectionToVerdict(parsed)
				c.Parsed, c.Action, c.Severity, c.Findings = true, v.Action, v.Severity, v.Findings
			}
		}
	}
	p.mu.Lock()
	p.calls[sid] = append(p.calls[sid], c)
	p.inflight[sid]--
	p.mu.Unlock()
	return resp, err
}

func (p *s7RecordingProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, cb func(StreamChunk)) (*ChatUsage, error) {
	return p.inner.ChatCompletionStream(ctx, req, cb)
}

// RecordJudgeCalls wraps the hook judge's provider. Call once after boot.
func (e *S7Engine) RecordJudgeCalls() bool {
	j := e.api.hookJudge.Load()
	if j == nil || j.provider == nil {
		return false
	}
	rec := &s7RecordingProvider{inner: j.provider, calls: map[string][]S7JudgeCall{}, inflight: map[string]int{}}
	j.provider = rec
	e.judgeRec = rec
	return true
}

// TakeJudgeCalls returns and clears the judge requests made for sessionID,
// after waiting (up to 3 s) for a request the hook left running past its
// answer window to end, so a late call is not counted on the next one.
func (e *S7Engine) TakeJudgeCalls(sessionID string) []S7JudgeCall {
	if e.judgeRec == nil {
		return nil
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		e.judgeRec.mu.Lock()
		n := e.judgeRec.inflight[sessionID]
		e.judgeRec.mu.Unlock()
		if n <= 0 {
			break
		}
	}
	e.judgeRec.mu.Lock()
	defer e.judgeRec.mu.Unlock()
	out := e.judgeRec.calls[sessionID]
	delete(e.judgeRec.calls, sessionID)
	return out
}
