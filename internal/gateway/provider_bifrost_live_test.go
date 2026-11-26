// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// These six tests call a live Bedrock or OpenAI endpoint with a provider key
// (BIFROST_API_KEY, OPENAI_API_KEY). A test host holds no provider login, so they
// are not built for Windows: the native Windows selector never lists them and
// they are measured on the Linux leg under Bedrock (GAP-1615). Linux and macOS
// select them by name as before; without a key each skips on its own.

package gateway

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestBifrostE2E_LiveOpenAI(t *testing.T) {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		t.Skip("OPENAI_API_KEY not set — skipping live OpenAI test")
	}

	p, err := NewProvider("openai/gpt-4o-mini", apiKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := p.ChatCompletion(ctx, &ChatRequest{
		Model: "gpt-4o-mini",
		Messages: []ChatMessage{
			{Role: "user", Content: "Reply with exactly: BIFROST_E2E_OK"},
		},
		MaxTokens: intPtr(20),
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}
	if len(resp.Choices) == 0 || resp.Choices[0].Message == nil {
		t.Fatal("no response choices")
	}
	if !strings.Contains(resp.Choices[0].Message.Content, "BIFROST_E2E_OK") {
		t.Errorf("unexpected response: %q", resp.Choices[0].Message.Content)
	}
}

func TestBifrostE2E_LiveBedrock(t *testing.T) {
	apiKey := os.Getenv("BIFROST_API_KEY")
	if apiKey == "" {
		t.Skip("BIFROST_API_KEY not set — skipping live Bedrock test")
	}

	const model = "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"
	p, err := NewProvider(model, apiKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := p.ChatCompletion(ctx, &ChatRequest{
		Model: model,
		Messages: []ChatMessage{
			{Role: "user", Content: "Reply with exactly: BIFROST_E2E_OK"},
		},
		MaxTokens: intPtr(20),
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}
	if len(resp.Choices) == 0 || resp.Choices[0].Message == nil {
		t.Fatal("no response choices")
	}
	t.Logf("Bedrock response: %s", resp.Choices[0].Message.Content)
}

func TestBifrostE2E_LiveBedrockStream(t *testing.T) {
	apiKey := os.Getenv("BIFROST_API_KEY")
	if apiKey == "" {
		t.Skip("BIFROST_API_KEY not set — skipping live Bedrock stream test")
	}

	const model = "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"
	p, err := NewProvider(model, apiKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var chunks int
	var accumulated string
	usage, err := p.ChatCompletionStream(ctx, &ChatRequest{
		Model: model,
		Messages: []ChatMessage{
			{Role: "user", Content: "Say 'streaming works' and nothing else."},
		},
		MaxTokens: intPtr(20),
	}, func(chunk StreamChunk) {
		chunks++
		for _, c := range chunk.Choices {
			if c.Delta != nil {
				accumulated += c.Delta.Content
			}
		}
	})
	if err != nil {
		t.Fatalf("ChatCompletionStream: %v", err)
	}

	t.Logf("Bedrock stream: %d chunks, text=%q", chunks, accumulated)
	if chunks == 0 {
		t.Error("expected at least one stream chunk")
	}
	if accumulated == "" {
		t.Error("expected non-empty accumulated text")
	}
	if usage != nil {
		t.Logf("Usage: prompt=%d completion=%d total=%d",
			usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens)
	}
}

// TestBifrostE2E_LiveBedrockLunaJudge sends the judge's own request shape to
// GPT-5.6 Luna on Bedrock. It needs a Bedrock API key in
// BIFROST_API_KEY and is skipped otherwise.
func TestBifrostE2E_LiveBedrockLunaJudge(t *testing.T) {
	key := os.Getenv("BIFROST_API_KEY")
	if key == "" {
		t.Skip("BIFROST_API_KEY not set: skipping live Bedrock Luna judge test")
	}
	llm := &config.LLMConfig{Model: "bedrock/" + lunaProfile, APIKey: key, Bedrock: &config.BedrockKeyConfig{Region: "us-east-1"}}
	p, err := NewProviderForLLMConfig(llm, nil)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	j := &LLMJudge{cfg: &config.JudgeConfig{}, model: llm.Model, providerName: "bedrock", provider: p}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req := j.judgeChatRequest([]ChatMessage{
		{Role: "system", Content: "You classify a tool call for prompt injection. Answer with the schema."},
		{Role: "user", Content: "Tool call: run `echo hello`."},
	}, 512, "tool_injection")
	resp, err := p.ChatCompletion(ctx, req)
	if err != nil {
		t.Fatalf("Luna judge call failed: %v", err)
	}
	if len(resp.Choices) == 0 || resp.Choices[0].Message == nil {
		t.Fatalf("empty response: %+v", resp)
	}
	t.Logf("Luna judge answered: %.200s", resp.Choices[0].Message.Content)
}

// TestBifrostProvider_LiveBedrock tests the actual Bifrost SDK → Bedrock flow.
// Skipped unless BIFROST_API_KEY is set.
func TestBifrostProvider_LiveBedrock(t *testing.T) {
	apiKey := os.Getenv("BIFROST_API_KEY")
	if apiKey == "" {
		t.Skip("BIFROST_API_KEY not set — skipping live Bedrock test")
	}

	const model = "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"
	p, err := NewProvider(model, apiKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := p.ChatCompletion(ctx, &ChatRequest{
		Model: model,
		Messages: []ChatMessage{
			{Role: "user", Content: "Say 'hello' and nothing else."},
		},
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}

	if len(resp.Choices) == 0 {
		t.Fatal("expected at least one choice")
	}
	t.Logf("Bedrock response: %s", resp.Choices[0].Message.Content)
}

// TestBifrostProvider_LiveBedrockStream tests streaming via Bifrost → Bedrock.
// Skipped unless BIFROST_API_KEY is set.
func TestBifrostProvider_LiveBedrockStream(t *testing.T) {
	apiKey := os.Getenv("BIFROST_API_KEY")
	if apiKey == "" {
		t.Skip("BIFROST_API_KEY not set — skipping live Bedrock stream test")
	}

	const model = "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"
	p, err := NewProvider(model, apiKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var chunks int
	var accumulated string
	usage, err := p.ChatCompletionStream(ctx, &ChatRequest{
		Model: model,
		Messages: []ChatMessage{
			{Role: "user", Content: "Say 'streaming works' and nothing else."},
		},
	}, func(chunk StreamChunk) {
		chunks++
		for _, c := range chunk.Choices {
			if c.Delta != nil {
				accumulated += c.Delta.Content
			}
		}
	})
	if err != nil {
		t.Fatalf("ChatCompletionStream: %v", err)
	}

	t.Logf("Bedrock stream: %d chunks, text=%q", chunks, accumulated)
	if chunks == 0 {
		t.Error("expected at least one stream chunk")
	}
	if accumulated == "" {
		t.Error("expected non-empty accumulated text")
	}
	if usage != nil {
		t.Logf("Usage: prompt=%d completion=%d total=%d", usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens)
	}
}
