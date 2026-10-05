// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestAppleFMProviderUsesOnDeviceBridge(t *testing.T) {
	restore := swapAppleFMForTest(t, func(_ context.Context, call appleFMCall) (string, error) {
		if call.instructions == "" || call.prompt == "" {
			t.Fatalf("call = %#v, want system instructions and a user prompt", call)
		}
		if call.maxTokens != 32 {
			t.Fatalf("maxTokens = %d, want 32", call.maxTokens)
		}
		return "verdict:" + call.prompt, nil
	})
	defer restore()

	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "apple-fm",
		Model:    "apple-fm/system",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	maxTokens := 32
	resp, err := provider.ChatCompletion(context.Background(), &ChatRequest{
		Messages: []ChatMessage{
			{Role: "system", Content: "Return JSON"},
			{Role: "user", Content: "hello"},
		},
		MaxTokens: &maxTokens,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Choices) != 1 || resp.Choices[0].Message == nil {
		t.Fatalf("choices = %#v", resp.Choices)
	}
	if got := resp.Choices[0].Message.Content; got != "verdict:hello" {
		t.Fatalf("content = %q", got)
	}
	if resp.Model != "apple-fm/system" {
		t.Fatalf("model = %q", resp.Model)
	}
}

func TestAppleFMStockBuildRefusesToLink(t *testing.T) {
	previous := appleFMAvailable
	appleFMAvailable = false
	t.Cleanup(func() { appleFMAvailable = previous })

	_, err := NewProvider("apple-fm/system", "")
	if err == nil || !strings.Contains(err.Error(), "-tags applefm") {
		t.Fatalf("err = %v, want the applefm build instructions", err)
	}
}

func TestAppleFMJudgeDoesNotRequireAPIKey(t *testing.T) {
	if !llmJudgeAllowsEmptyAPIKey(config.LLMConfig{Model: "apple-fm/system"}, nil) {
		t.Fatal("apple-fm judge must run without an API key")
	}
	if !(config.LLMConfig{Provider: "apple-fm"}).IsLocalProvider() {
		t.Fatal("apple-fm is a local provider")
	}
}

func TestAppleFMCallSeparatesInstructions(t *testing.T) {
	maxTokens := 8
	temperature := 0.0
	call := appleFMCallFromRequest(&ChatRequest{
		Messages: []ChatMessage{
			{Role: "system", Content: "policy"},
			{Role: "user", Content: "sample"},
		},
		MaxTokens:   &maxTokens,
		Temperature: &temperature,
	})
	if call.instructions != "policy" || call.prompt != "sample" {
		t.Fatalf("call = %#v", call)
	}
	if call.maxTokens != 8 || call.temperature != 0 {
		t.Fatalf("generation = tokens %d temperature %v", call.maxTokens, call.temperature)
	}
}

func swapAppleFMForTest(t *testing.T, complete func(context.Context, appleFMCall) (string, error)) func() {
	t.Helper()
	previousAvailable := appleFMAvailable
	previousComplete := appleFMComplete
	appleFMAvailable = true
	appleFMComplete = complete
	return func() {
		appleFMAvailable = previousAvailable
		appleFMComplete = previousComplete
	}
}

func TestAppleFMContextHonoredBeforeBridge(t *testing.T) {
	restore := swapAppleFMForTest(t, func(context.Context, appleFMCall) (string, error) {
		t.Fatal("bridge was called after the context was cancelled")
		return "", nil
	})
	defer restore()

	provider, err := newAppleFMProvider("system")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = provider.ChatCompletion(ctx, &ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected the cancelled context to fail the call")
	}
}
