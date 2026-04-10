package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGeminiNative_TranslateRequest(t *testing.T) {
	temp := 0.7
	req := &ChatRequest{
		Model: "gemini-2.0-flash",
		Messages: []ChatMessage{
			{Role: "system", Content: "You are helpful."},
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "Hi there!"},
			{Role: "user", Content: "How are you?"},
		},
		MaxTokens:   intPtr(1024),
		Temperature: &temp,
	}

	gReq := translateGeminiRequest(req)

	// System instruction extracted.
	if gReq.SystemInstruction == nil {
		t.Fatal("expected systemInstruction, got nil")
	}
	if len(gReq.SystemInstruction.Parts) != 1 || gReq.SystemInstruction.Parts[0].Text != "You are helpful." {
		t.Errorf("systemInstruction = %+v, want 'You are helpful.'", gReq.SystemInstruction)
	}

	// Contents should have 3 messages (no system).
	if len(gReq.Contents) != 3 {
		t.Fatalf("contents len = %d, want 3", len(gReq.Contents))
	}
	if gReq.Contents[0].Role != "user" {
		t.Errorf("contents[0].role = %q, want user", gReq.Contents[0].Role)
	}
	if gReq.Contents[1].Role != "model" {
		t.Errorf("contents[1].role = %q, want model", gReq.Contents[1].Role)
	}
	if gReq.Contents[2].Role != "user" {
		t.Errorf("contents[2].role = %q, want user", gReq.Contents[2].Role)
	}

	// GenerationConfig.
	if gReq.GenerationConfig == nil {
		t.Fatal("expected generationConfig, got nil")
	}
	if gReq.GenerationConfig.MaxOutputTokens == nil || *gReq.GenerationConfig.MaxOutputTokens != 1024 {
		t.Errorf("maxOutputTokens = %v, want 1024", gReq.GenerationConfig.MaxOutputTokens)
	}
	if gReq.GenerationConfig.Temperature == nil || *gReq.GenerationConfig.Temperature != 0.7 {
		t.Errorf("temperature = %v, want 0.7", gReq.GenerationConfig.Temperature)
	}
}

func TestGeminiNative_TranslateRequest_ToolMessages(t *testing.T) {
	toolCallsJSON, _ := json.Marshal([]map[string]interface{}{
		{
			"id":   "call_1",
			"type": "function",
			"function": map[string]interface{}{
				"name":      "get_weather",
				"arguments": `{"city":"SF"}`,
			},
		},
	})

	req := &ChatRequest{
		Model: "gemini-2.0-flash",
		Messages: []ChatMessage{
			{Role: "user", Content: "What's the weather?"},
			{Role: "assistant", Content: "", ToolCalls: toolCallsJSON},
			{Role: "tool", Content: `{"temp":72}`, Name: "get_weather", ToolCallID: "call_1"},
			{Role: "assistant", Content: "It's 72 degrees."},
		},
	}

	gReq := translateGeminiRequest(req)

	if len(gReq.Contents) != 4 {
		t.Fatalf("contents len = %d, want 4", len(gReq.Contents))
	}

	// Assistant with tool call -> model with functionCall part.
	if gReq.Contents[1].Role != "model" {
		t.Errorf("contents[1].role = %q, want model", gReq.Contents[1].Role)
	}
	if len(gReq.Contents[1].Parts) < 1 || gReq.Contents[1].Parts[0].FunctionCall == nil {
		t.Error("expected functionCall part in assistant message")
	}

	// Tool result -> function role with functionResponse.
	if gReq.Contents[2].Role != "function" {
		t.Errorf("contents[2].role = %q, want function", gReq.Contents[2].Role)
	}
	if gReq.Contents[2].Parts[0].FunctionResponse == nil {
		t.Error("expected functionResponse in tool message")
	}
	if gReq.Contents[2].Parts[0].FunctionResponse.Name != "get_weather" {
		t.Errorf("functionResponse name = %q, want get_weather", gReq.Contents[2].Parts[0].FunctionResponse.Name)
	}
}

func TestGeminiNative_TranslateResponse(t *testing.T) {
	gResp := &geminiResponse{
		Candidates: []geminiCandidate{{
			Content: &geminiContent{
				Role:  "model",
				Parts: []geminiPart{{Text: "Hello, world!"}},
			},
			FinishReason: "STOP",
		}},
		UsageMetadata: &geminiUsage{
			PromptTokenCount:     10,
			CandidatesTokenCount: 5,
			TotalTokenCount:      15,
		},
	}

	resp := translateGeminiResponse(gResp, "gemini-2.0-flash")

	if resp.Object != "chat.completion" {
		t.Errorf("object = %q, want chat.completion", resp.Object)
	}
	if resp.Model != "gemini-2.0-flash" {
		t.Errorf("model = %q, want gemini-2.0-flash", resp.Model)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("choices len = %d, want 1", len(resp.Choices))
	}
	if resp.Choices[0].Message.Content != "Hello, world!" {
		t.Errorf("content = %q, want 'Hello, world!'", resp.Choices[0].Message.Content)
	}
	if resp.Choices[0].FinishReason == nil || *resp.Choices[0].FinishReason != "stop" {
		t.Errorf("finish_reason = %v, want stop", resp.Choices[0].FinishReason)
	}
	if resp.Usage == nil {
		t.Fatal("usage is nil")
	}
	if resp.Usage.PromptTokens != 10 {
		t.Errorf("prompt_tokens = %d, want 10", resp.Usage.PromptTokens)
	}
	if resp.Usage.CompletionTokens != 5 {
		t.Errorf("completion_tokens = %d, want 5", resp.Usage.CompletionTokens)
	}
	if resp.Usage.TotalTokens != 15 {
		t.Errorf("total_tokens = %d, want 15", resp.Usage.TotalTokens)
	}
}

func TestGeminiNative_TranslateResponse_ToolCalls(t *testing.T) {
	gResp := &geminiResponse{
		Candidates: []geminiCandidate{{
			Content: &geminiContent{
				Role: "model",
				Parts: []geminiPart{
					{FunctionCall: &geminiFunctionCall{Name: "get_weather", Args: map[string]interface{}{"city": "SF"}}},
				},
			},
			FinishReason: "STOP",
		}},
	}

	resp := translateGeminiResponse(gResp, "gemini-2.0-flash")

	if len(resp.Choices) != 1 {
		t.Fatalf("choices len = %d, want 1", len(resp.Choices))
	}
	if resp.Choices[0].Message.ToolCalls == nil {
		t.Fatal("expected tool_calls, got nil")
	}
	// finish_reason should be "tool_calls" when there are tool calls.
	if *resp.Choices[0].FinishReason != "tool_calls" {
		t.Errorf("finish_reason = %q, want tool_calls", *resp.Choices[0].FinishReason)
	}

	var tcs []map[string]interface{}
	if err := json.Unmarshal(resp.Choices[0].Message.ToolCalls, &tcs); err != nil {
		t.Fatalf("unmarshal tool_calls: %v", err)
	}
	if len(tcs) != 1 {
		t.Fatalf("tool_calls len = %d, want 1", len(tcs))
	}
	fn := tcs[0]["function"].(map[string]interface{})
	if fn["name"] != "get_weather" {
		t.Errorf("tool_call name = %v, want get_weather", fn["name"])
	}
}

func TestGeminiNative_FinishReasonMapping(t *testing.T) {
	tests := []struct {
		gemini string
		openai string
	}{
		{"STOP", "stop"},
		{"MAX_TOKENS", "length"},
		{"SAFETY", "content_filter"},
		{"RECITATION", "content_filter"},
		{"", "stop"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q->%q", tt.gemini, tt.openai), func(t *testing.T) {
			got := mapGeminiFinishReason(tt.gemini)
			if got != tt.openai {
				t.Errorf("mapGeminiFinishReason(%q) = %q, want %q", tt.gemini, got, tt.openai)
			}
		})
	}
}

func TestGeminiNative_URLConstruction(t *testing.T) {
	p := &geminiNativeProvider{model: "gemini-2.0-flash", apiKey: "AIzaTestKey123"}

	// Non-streaming URL.
	got := p.generateURL(false)
	want := "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=AIzaTestKey123"
	if got != want {
		t.Errorf("generateURL(false) =\n  %q\nwant\n  %q", got, want)
	}

	// Streaming URL.
	got = p.generateURL(true)
	want = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse&key=AIzaTestKey123"
	if got != want {
		t.Errorf("generateURL(true) =\n  %q\nwant\n  %q", got, want)
	}

	// Custom base URL.
	p2 := &geminiNativeProvider{model: "gemini-pro", apiKey: "key", baseURL: "http://localhost:8080"}
	got = p2.generateURL(false)
	want = "http://localhost:8080/models/gemini-pro:generateContent?key=key"
	if got != want {
		t.Errorf("custom base generateURL(false) =\n  %q\nwant\n  %q", got, want)
	}
}

func TestGeminiNative_EndToEnd(t *testing.T) {
	var gotContentType string
	var gotBody geminiRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify key is in query param, not Authorization header.
		if r.URL.Query().Get("key") != "test-api-key" {
			t.Errorf("expected key=test-api-key in query, got %q", r.URL.RawQuery)
		}
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("unexpected Authorization header: %q", auth)
		}
		gotContentType = r.Header.Get("Content-Type")
		json.NewDecoder(r.Body).Decode(&gotBody)

		// Verify URL path contains :generateContent.
		if !strings.Contains(r.URL.Path, ":generateContent") {
			t.Errorf("URL path = %q, want :generateContent", r.URL.Path)
		}

		resp := geminiResponse{
			Candidates: []geminiCandidate{{
				Content: &geminiContent{
					Role:  "model",
					Parts: []geminiPart{{Text: "I'm Gemini!"}},
				},
				FinishReason: "STOP",
			}},
			UsageMetadata: &geminiUsage{
				PromptTokenCount:     8,
				CandidatesTokenCount: 4,
				TotalTokenCount:      12,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &geminiNativeProvider{model: "gemini-2.0-flash", apiKey: "test-api-key", baseURL: srv.URL}
	resp, err := p.ChatCompletion(context.Background(), &ChatRequest{
		Model: "gemini/gemini-2.0-flash",
		Messages: []ChatMessage{
			{Role: "system", Content: "Be concise."},
			{Role: "user", Content: "Who are you?"},
		},
		MaxTokens: intPtr(256),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}

	// Verify request was translated.
	if gotBody.SystemInstruction == nil {
		t.Error("expected systemInstruction in request")
	}
	if len(gotBody.Contents) != 1 {
		t.Errorf("contents len = %d, want 1", len(gotBody.Contents))
	}

	// Verify response was translated back to OpenAI format.
	if resp.Object != "chat.completion" {
		t.Errorf("object = %q, want chat.completion", resp.Object)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("choices len = %d, want 1", len(resp.Choices))
	}
	if resp.Choices[0].Message.Content != "I'm Gemini!" {
		t.Errorf("content = %q, want 'I'm Gemini!'", resp.Choices[0].Message.Content)
	}
	if resp.Usage == nil || resp.Usage.TotalTokens != 12 {
		t.Errorf("usage total = %v, want 12", resp.Usage)
	}
}

func TestGeminiNative_StreamEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify streaming URL params.
		if !strings.Contains(r.URL.RawQuery, "alt=sse") {
			t.Errorf("expected alt=sse in query, got %q", r.URL.RawQuery)
		}
		if !strings.Contains(r.URL.Path, ":streamGenerateContent") {
			t.Errorf("URL path = %q, want :streamGenerateContent", r.URL.Path)
		}

		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)

		// Chunk 1: partial text.
		chunk1 := geminiResponse{
			Candidates: []geminiCandidate{{
				Content: &geminiContent{
					Role:  "model",
					Parts: []geminiPart{{Text: "Hello"}},
				},
			}},
		}
		data1, _ := json.Marshal(chunk1)
		fmt.Fprintf(w, "data: %s\n\n", data1)
		flusher.Flush()

		// Chunk 2: more text + finish + usage.
		chunk2 := geminiResponse{
			Candidates: []geminiCandidate{{
				Content: &geminiContent{
					Role:  "model",
					Parts: []geminiPart{{Text: " World"}},
				},
				FinishReason: "STOP",
			}},
			UsageMetadata: &geminiUsage{
				PromptTokenCount:     5,
				CandidatesTokenCount: 3,
				TotalTokenCount:      8,
			},
		}
		data2, _ := json.Marshal(chunk2)
		fmt.Fprintf(w, "data: %s\n\n", data2)
		flusher.Flush()
	}))
	defer srv.Close()

	p := &geminiNativeProvider{model: "gemini-2.0-flash", apiKey: "test-key", baseURL: srv.URL}

	var chunks []StreamChunk
	usage, err := p.ChatCompletionStream(context.Background(), &ChatRequest{
		Model: "gemini/gemini-2.0-flash",
		Messages: []ChatMessage{
			{Role: "user", Content: "Hello"},
		},
	}, func(chunk StreamChunk) {
		chunks = append(chunks, chunk)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have received text chunks + finish chunk.
	if len(chunks) < 2 {
		t.Fatalf("chunks len = %d, want >= 2", len(chunks))
	}

	// Verify assembled text.
	var assembled strings.Builder
	for _, c := range chunks {
		if len(c.Choices) > 0 && c.Choices[0].Delta != nil {
			assembled.WriteString(c.Choices[0].Delta.Content)
		}
	}
	if assembled.String() != "Hello World" {
		t.Errorf("assembled text = %q, want 'Hello World'", assembled.String())
	}

	// Verify a finish reason was emitted.
	lastChunk := chunks[len(chunks)-1]
	if len(lastChunk.Choices) == 0 || lastChunk.Choices[0].FinishReason == nil {
		t.Error("expected finish_reason in last chunk")
	} else if *lastChunk.Choices[0].FinishReason != "stop" {
		t.Errorf("finish_reason = %q, want stop", *lastChunk.Choices[0].FinishReason)
	}

	// Verify usage.
	if usage == nil {
		t.Fatal("expected usage, got nil")
	}
	if usage.TotalTokens != 8 {
		t.Errorf("usage total = %d, want 8", usage.TotalTokens)
	}
}

func TestGeminiNative_Tools(t *testing.T) {
	toolsJSON, _ := json.Marshal([]map[string]interface{}{
		{
			"type": "function",
			"function": map[string]interface{}{
				"name":        "get_weather",
				"description": "Get current weather",
				"parameters": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"city": map[string]string{"type": "string"},
					},
				},
			},
		},
	})

	req := &ChatRequest{
		Model: "gemini-2.0-flash",
		Messages: []ChatMessage{
			{Role: "user", Content: "Weather in SF?"},
		},
		Tools: toolsJSON,
	}

	gReq := translateGeminiRequest(req)

	if len(gReq.Tools) != 1 {
		t.Fatalf("tools len = %d, want 1", len(gReq.Tools))
	}
	if len(gReq.Tools[0].FunctionDeclarations) != 1 {
		t.Fatalf("functionDeclarations len = %d, want 1", len(gReq.Tools[0].FunctionDeclarations))
	}
	if gReq.Tools[0].FunctionDeclarations[0].Name != "get_weather" {
		t.Errorf("tool name = %q, want get_weather", gReq.Tools[0].FunctionDeclarations[0].Name)
	}
}
