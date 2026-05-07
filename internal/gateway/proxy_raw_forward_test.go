package gateway

import (
	"strings"
	"testing"
)

func TestExtractRawForwardCompletionNonStreaming(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl-test",
		"object": "chat.completion",
		"choices": [
			{
				"index": 0,
				"message": {
					"role": "assistant",
					"content": "OK"
				},
				"finish_reason": "stop"
			}
		],
		"usage": {
			"prompt_tokens": 10,
			"completion_tokens": 2,
			"total_tokens": 12
		}
	}`)

	got, usage := extractRawForwardCompletion(body, false)
	if got != "OK" {
		t.Fatalf("completion = %q, want %q", got, "OK")
	}
	if usage == nil {
		t.Fatalf("usage = nil, want non-nil")
	}
	if usage.PromptTokens != 10 || usage.CompletionTokens != 2 {
		t.Fatalf("usage = %+v, want prompt=10 completion=2", usage)
	}
}

func TestExtractRawForwardCompletionStreaming(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"O"}}]}`,
		`data: {"choices":[{"delta":{"content":"K"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	got, usage := extractRawForwardCompletion(body, true)
	if got != "OK" {
		t.Fatalf("completion = %q, want %q", got, "OK")
	}
	if usage != nil {
		t.Fatalf("usage = %+v, want nil for streaming chunks", usage)
	}
}

func TestExtractRawForwardCompletionIgnoresRawRequestText(t *testing.T) {
	body := []byte(`{
		"choices": [
			{
				"message": {
					"role": "assistant",
					"content": "OK"
				}
			}
		],
		"messages": [
			{
				"role": "system",
				"content": "SOUL.md AGENTS.md MEMORY.md"
			}
		]
	}`)

	got, _ := extractRawForwardCompletion(body, false)
	if got != "OK" {
		t.Fatalf("completion = %q, want assistant output only", got)
	}
}
