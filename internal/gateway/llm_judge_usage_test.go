// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
)

type judgeUsageSink struct{ ch chan modelusage.Record }

func (s judgeUsageSink) Emit(_ context.Context, r modelusage.Record) { s.ch <- r }

type fixedUsageProvider struct{ resp *ChatResponse }

func (p fixedUsageProvider) ChatCompletion(context.Context, *ChatRequest) (*ChatResponse, error) {
	return p.resp, nil
}
func (p fixedUsageProvider) ChatCompletionStream(context.Context, *ChatRequest, func(StreamChunk)) (*ChatUsage, error) {
	return nil, nil
}

func TestJudgeCallIsRecordedWithRoleJudgeAndProviderUsage(t *testing.T) {
	sink := judgeUsageSink{ch: make(chan modelusage.Record, 4)}
	engine := modelusage.NewEngine(sink)
	engine.Apply(config.TokenomicsConfig{Enabled: true}, config.PricingConfig{})
	processModelUsage.Store(engine)
	defer func() {
		processModelUsage.Store(nil)
		engine.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	}()
	j := &LLMJudge{
		cfg: &config.JudgeConfig{}, model: "claude-haiku-4-5", providerName: "anthropic", calls: nil,
		provider: fixedUsageProvider{resp: &ChatResponse{Model: "claude-haiku-4-5-20251001", Usage: &ChatUsage{PromptTokens: 120, CompletionTokens: 7}}},
	}
	if _, err := j.chat(context.Background(), "injection", &ChatRequest{}); err != nil {
		t.Fatal(err)
	}
	select {
	case rec := <-sink.ch:
		if rec.Facts.CallRole != modelusage.RoleJudge || rec.Facts.Surface != "injection" ||
			rec.Usage.Input != 120 || rec.Usage.Output != 7 || rec.Usage.ResponseModel != "claude-haiku-4-5-20251001" {
			t.Fatalf("%+v", rec)
		}
		if rec.Cost.USD != nil {
			t.Fatalf("no price table: cost must be absent, got %+v", rec.Cost)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the judge call was not recorded")
	}
}

func TestJudgeCallWithNoRecorderIsUntouched(t *testing.T) {
	processModelUsage.Store(nil)
	j := &LLMJudge{cfg: &config.JudgeConfig{}, provider: fixedUsageProvider{resp: &ChatResponse{}}}
	if _, err := j.chat(context.Background(), "pii", &ChatRequest{}); err != nil {
		t.Fatal(err)
	}
}
