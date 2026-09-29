// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// bedrockToAnthropicRequest translates a Bedrock Invoke request into an
// Anthropic Messages API request. The Bedrock body already uses messages[]
// format; this function adds the model field, sets stream:true for streaming
// paths, and rewrites the URL to /v1/messages.
func bedrockToAnthropicRequest(body []byte, urlPath string, targetModel string) (translatedBody []byte, translatedPath string) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, urlPath
	}

	modelJSON, _ := json.Marshal(targetModel)
	raw["model"] = modelJSON

	if strings.Contains(urlPath, "stream") {
		raw["stream"] = json.RawMessage("true")
	}

	// Bedrock doesn't use max_tokens in body (uses inferenceConfig),
	// but Anthropic requires it. Extract from inferenceConfig if present.
	if _, hasMax := raw["max_tokens"]; !hasMax {
		if cfgRaw, ok := raw["inferenceConfig"]; ok {
			var cfg struct {
				MaxTokens   int     `json:"maxTokens"`
				Temperature float64 `json:"temperature"`
				TopP        float64 `json:"topP"`
			}
			if json.Unmarshal(cfgRaw, &cfg) == nil && cfg.MaxTokens > 0 {
				maxJSON, _ := json.Marshal(cfg.MaxTokens)
				raw["max_tokens"] = maxJSON
			}
			delete(raw, "inferenceConfig")
		}
	}
	if _, hasMax := raw["max_tokens"]; !hasMax {
		raw["max_tokens"] = json.RawMessage("4096")
	}

	out, err := json.Marshal(raw)
	if err != nil {
		return body, urlPath
	}
	return out, "/v1/messages"
}

// bedrockToAnthropicHeaders rewrites auth headers from Bedrock format
// (Authorization: Bearer ABSK*) to Anthropic format (x-api-key + anthropic-version).
func bedrockToAnthropicHeaders(req *http.Request, apiKey string) {
	req.Header.Del("Authorization")
	req.Header.Set("x-api-key", apiKey)
	if req.Header.Get("anthropic-version") == "" {
		req.Header.Set("anthropic-version", "2023-06-01")
	}
}

// anthropicSSEToBedrokEventstream reads an Anthropic SSE streaming response
// and translates it to Bedrock eventstream binary format, writing frames
// to w. This allows Claude Code in Bedrock mode to consume responses from
// an Anthropic Messages API endpoint (e.g. DGX LiteLLM).
func anthropicSSEToBedrockEventstream(w http.ResponseWriter, resp *http.Response) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("response writer does not support flushing")
	}

	w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
	w.WriteHeader(http.StatusOK)

	emit := func(eventType string, payload map[string]any) {
		if err := writeBedrockEventStreamFrame(w, eventType, payload); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] bedrock-translate frame %q error: %v\n", eventType, err)
		}
		flusher.Flush()
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	var totalInputTokens, totalOutputTokens int

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var event struct {
			Type    string `json:"type"`
			Message *struct {
				Role  string `json:"role"`
				Model string `json:"model"`
				Usage *struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Index        int `json:"index"`
			ContentBlock *struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content_block"`
			Delta *struct {
				Type       string `json:"type"`
				Text       string `json:"text"`
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
			Usage *struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}

		switch event.Type {
		case "message_start":
			role := "assistant"
			if event.Message != nil {
				if event.Message.Role != "" {
					role = event.Message.Role
				}
				if event.Message.Usage != nil {
					totalInputTokens = event.Message.Usage.InputTokens
				}
			}
			emit("messageStart", map[string]any{
				"role": role,
				"p":    "",
			})

		case "content_block_start":
			// Bedrock doesn't have an explicit contentBlockStart event,
			// but some clients handle it gracefully. Skip for compatibility.

		case "content_block_delta":
			text := ""
			if event.Delta != nil {
				text = event.Delta.Text
			}
			emit("contentBlockDelta", map[string]any{
				"contentBlockIndex": event.Index,
				"delta":             map[string]any{"text": text},
				"p":                 "",
			})

		case "content_block_stop":
			emit("contentBlockStop", map[string]any{
				"contentBlockIndex": event.Index,
				"p":                 "",
			})

		case "message_delta":
			stopReason := "end_turn"
			if event.Delta != nil && event.Delta.StopReason != "" {
				stopReason = event.Delta.StopReason
			}
			if event.Usage != nil {
				totalOutputTokens = event.Usage.OutputTokens
			}
			emit("messageStop", map[string]any{
				"stopReason": stopReason,
				"p":          "",
			})

		case "message_stop":
			emit("metadata", map[string]any{
				"usage": map[string]int{
					"inputTokens":  totalInputTokens,
					"outputTokens": totalOutputTokens,
					"totalTokens":  totalInputTokens + totalOutputTokens,
				},
				"metrics": map[string]int{"latencyMs": 0},
				"p":       "",
			})
		}
	}

	return scanner.Err()
}

// bedrockToOpenAIRequest translates a Bedrock Invoke request into an
// OpenAI Chat Completions request. Converts Anthropic-style messages to
// OpenAI format and rewrites the URL path.
func bedrockToOpenAIRequest(body []byte, urlPath string, targetModel string) (translatedBody []byte, translatedPath string) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, urlPath
	}

	oaiReq := map[string]interface{}{
		"model": targetModel,
	}

	if strings.Contains(urlPath, "stream") {
		oaiReq["stream"] = true
	}

	// Convert messages from Anthropic format to OpenAI format.
	var msgs []json.RawMessage
	if rawMsgs, ok := raw["messages"]; ok {
		var anthropicMsgs []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(rawMsgs, &anthropicMsgs) == nil {
			oaiMsgs := make([]map[string]string, 0, len(anthropicMsgs))
			for _, m := range anthropicMsgs {
				content := extractTextContent(m.Content)
				oaiMsgs = append(oaiMsgs, map[string]string{
					"role":    m.Role,
					"content": content,
				})
			}
			b, _ := json.Marshal(oaiMsgs)
			oaiReq["messages"] = json.RawMessage(b)
		} else {
			oaiReq["messages"] = msgs
		}
	}

	// Transfer system prompt.
	if sys, ok := raw["system"]; ok {
		var sysStr string
		if json.Unmarshal(sys, &sysStr) == nil && sysStr != "" {
			sysMsg := []map[string]string{{"role": "system", "content": sysStr}}
			if existing, ok := oaiReq["messages"]; ok {
				var existingMsgs []map[string]string
				b, _ := json.Marshal(existing)
				if json.Unmarshal(b, &existingMsgs) == nil {
					oaiReq["messages"] = append(sysMsg, existingMsgs...)
				}
			}
		}
	}

	// Transfer max_tokens / inferenceConfig.
	if maxTok, ok := raw["max_tokens"]; ok {
		oaiReq["max_tokens"] = maxTok
	} else if cfgRaw, ok := raw["inferenceConfig"]; ok {
		var cfg struct {
			MaxTokens   int     `json:"maxTokens"`
			Temperature float64 `json:"temperature"`
			TopP        float64 `json:"topP"`
		}
		if json.Unmarshal(cfgRaw, &cfg) == nil {
			if cfg.MaxTokens > 0 {
				oaiReq["max_tokens"] = cfg.MaxTokens
			}
			if cfg.Temperature > 0 {
				oaiReq["temperature"] = cfg.Temperature
			}
			if cfg.TopP > 0 {
				oaiReq["top_p"] = cfg.TopP
			}
		}
	}
	if _, ok := oaiReq["max_tokens"]; !ok {
		oaiReq["max_tokens"] = 4096
	}

	out, err := json.Marshal(oaiReq)
	if err != nil {
		return body, urlPath
	}
	return out, "/v1/chat/completions"
}

// extractTextContent extracts plain text from an Anthropic content field,
// which can be a string or an array of content blocks.
func extractTextContent(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) == nil {
		var parts []string
		for _, b := range blocks {
			if b.Type == "text" || b.Type == "" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "")
	}
	return string(raw)
}

// openAISSEToBedrockEventstream translates OpenAI streaming SSE responses
// to Bedrock eventstream format.
func openAISSEToBedrockEventstream(w http.ResponseWriter, resp *http.Response) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("response writer does not support flushing")
	}

	w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
	w.WriteHeader(http.StatusOK)

	emit := func(eventType string, payload map[string]any) {
		if err := writeBedrockEventStreamFrame(w, eventType, payload); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] bedrock-translate frame %q error: %v\n", eventType, err)
		}
		flusher.Flush()
	}

	emit("messageStart", map[string]any{"role": "assistant", "p": ""})

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	var totalOutputTokens int
	blockIndex := 0

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
					Role    string `json:"role"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				CompletionTokens int `json:"completion_tokens"`
				PromptTokens     int `json:"prompt_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(data), &chunk) != nil {
			continue
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		c := chunk.Choices[0]
		if c.Delta.Content != "" {
			emit("contentBlockDelta", map[string]any{
				"contentBlockIndex": blockIndex,
				"delta":             map[string]any{"text": c.Delta.Content},
				"p":                 "",
			})
		}
		if c.FinishReason != nil {
			emit("contentBlockStop", map[string]any{
				"contentBlockIndex": blockIndex,
				"p":                 "",
			})
			stopReason := "end_turn"
			if *c.FinishReason == "length" {
				stopReason = "max_tokens"
			}
			emit("messageStop", map[string]any{
				"stopReason": stopReason,
				"p":          "",
			})
		}
		if chunk.Usage != nil {
			totalOutputTokens = chunk.Usage.CompletionTokens
		}
	}

	emit("metadata", map[string]any{
		"usage": map[string]int{
			"inputTokens":  0,
			"outputTokens": totalOutputTokens,
			"totalTokens":  totalOutputTokens,
		},
		"metrics": map[string]int{"latencyMs": 0},
		"p":       "",
	})

	return scanner.Err()
}

// translateNonStreamingOpenAIToBedrock converts a non-streaming OpenAI
// Chat Completions response to Bedrock Converse response format.
func translateNonStreamingOpenAIToBedrock(w http.ResponseWriter, resp *http.Response) bool {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return false
	}

	var oaiResp struct {
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(body, &oaiResp) != nil || len(oaiResp.Choices) == 0 {
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return true
	}

	content := oaiResp.Choices[0].Message.Content
	stopReason := "end_turn"
	if oaiResp.Choices[0].FinishReason == "length" {
		stopReason = "max_tokens"
	}

	bedrockResp := map[string]any{
		"output": map[string]any{
			"message": map[string]any{
				"role":    "assistant",
				"content": []map[string]any{{"text": content}},
			},
		},
		"stopReason": stopReason,
		"usage": map[string]int{
			"inputTokens":  oaiResp.Usage.PromptTokens,
			"outputTokens": oaiResp.Usage.CompletionTokens,
			"totalTokens":  oaiResp.Usage.TotalTokens,
		},
		"metrics": map[string]int{"latencyMs": 0},
	}

	out, _ := json.Marshal(bedrockResp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(out)
	return true
}

// isBedrockInvokePath returns true if the URL path is a Bedrock Invoke or
// Converse path that needs translation when rerouted to a non-Bedrock provider.
func isBedrockInvokePath(path string) bool {
	return strings.Contains(path, "/invoke") || strings.Contains(path, "/converse")
}

// shouldTranslateBedrockToOpenAI returns true when a Bedrock-format request
// should be translated to OpenAI Chat Completions format (provider is "openai").
func shouldTranslateBedrockToOpenAI(urlPath string, decision *ModelRouterDecision) bool {
	if decision == nil || !decision.TargetURLOverride {
		return false
	}
	if !isBedrockInvokePath(urlPath) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(decision.Provider), "openai")
}

// shouldTranslateBedrockToAnthropic returns true when the semantic router
// has rerouted a Bedrock-format request to a non-Bedrock provider and
// format translation is needed. Returns false when the target is a
// Bedrock endpoint (URL contains "bedrock") since no translation is needed.
func shouldTranslateBedrockToAnthropic(urlPath string, decision *ModelRouterDecision) bool {
	if decision == nil || !decision.TargetURLOverride {
		return false
	}
	if !isBedrockInvokePath(urlPath) {
		return false
	}
	targetURL := strings.ToLower(decision.TargetURL)
	if strings.Contains(targetURL, "bedrock") {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(decision.Provider), "openai") {
		return false
	}
	return true
}

// translatePassthroughResponse wraps the upstream HTTP response and translates
// Anthropic SSE to Bedrock eventstream if the original request was Bedrock format
// but was rerouted to an Anthropic/OpenAI provider.
func translatePassthroughResponse(w http.ResponseWriter, resp *http.Response, originalPath string) (handled bool) {
	if !isBedrockInvokePath(originalPath) {
		return false
	}
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/event-stream") {
		// Non-streaming Anthropic response — translate JSON body format
		return translateNonStreamingAnthropicToBedrock(w, resp)
	}
	fmt.Fprintf(os.Stderr, "[guardrail] translating Anthropic SSE → Bedrock eventstream\n")
	if err := anthropicSSEToBedrockEventstream(w, resp); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] bedrock-translate error: %v\n", err)
	}
	return true
}

// translateNonStreamingAnthropicToBedrock converts a non-streaming Anthropic
// Messages response to Bedrock Converse response format.
func translateNonStreamingAnthropicToBedrock(w http.ResponseWriter, resp *http.Response) bool {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return false
	}

	var anthropicResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(body, &anthropicResp) != nil {
		// Can't parse — forward as-is
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return true
	}

	contentBlocks := make([]map[string]any, 0, len(anthropicResp.Content))
	for _, c := range anthropicResp.Content {
		contentBlocks = append(contentBlocks, map[string]any{"text": c.Text})
	}

	bedrockResp := map[string]any{
		"output": map[string]any{
			"message": map[string]any{
				"role":    "assistant",
				"content": contentBlocks,
			},
		},
		"stopReason": anthropicResp.StopReason,
		"usage": map[string]int{
			"inputTokens":  anthropicResp.Usage.InputTokens,
			"outputTokens": anthropicResp.Usage.OutputTokens,
			"totalTokens":  anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens,
		},
		"metrics": map[string]int{"latencyMs": 0},
	}

	out, _ := json.Marshal(bedrockResp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(out)
	return true
}

// zstdMagic is the first 4 bytes of a zstd-compressed frame.
var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// isZstdCompressed checks if data starts with the zstd magic bytes.
func isZstdCompressed(data []byte) bool {
	return len(data) >= 4 && bytes.Equal(data[:4], zstdMagic)
}
