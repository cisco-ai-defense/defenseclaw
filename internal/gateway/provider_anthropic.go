package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Anthropic provider — translates between OpenAI format and Anthropic Messages API
// ---------------------------------------------------------------------------

type anthropicProvider struct {
	model  string
	apiKey string
}

type anthropicRequest struct {
	Model       string              `json:"model"`
	Messages    []anthropicMessage  `json:"messages"`
	System      string              `json:"system,omitempty"`
	MaxTokens   int                 `json:"max_tokens"`
	Temperature *float64            `json:"temperature,omitempty"`
	TopP        *float64            `json:"top_p,omitempty"`
	Stream      bool                `json:"stream,omitempty"`
	Stop        json.RawMessage     `json:"stop_sequences,omitempty"`
	Tools       json.RawMessage     `json:"tools,omitempty"`
	ToolChoice  json.RawMessage     `json:"tool_choice,omitempty"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type anthropicResponse struct {
	ID         string             `json:"id"`
	Type       string             `json:"type"`
	Role       string             `json:"role"`
	Content    []anthropicContent `json:"content"`
	Model      string             `json:"model"`
	StopReason string             `json:"stop_reason"`
	Usage      *anthropicUsage    `json:"usage"`
}

type anthropicContent struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type anthropicUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

func (p *anthropicProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	aReq := p.translateRequest(req)
	aReq.Stream = false

	body, err := json.Marshal(aReq)
	if err != nil {
		return nil, fmt.Errorf("provider: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	var aResp anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&aResp); err != nil {
		return nil, fmt.Errorf("provider: decode response: %w", err)
	}

	return p.translateResponse(&aResp, req.Model), nil
}

func (p *anthropicProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
	aReq := p.translateRequest(req)
	aReq.Stream = true

	body, err := json.Marshal(aReq)
	if err != nil {
		return nil, fmt.Errorf("provider: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: stream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	return p.readAnthropicSSE(resp.Body, req.Model, chunkCb)
}

func (p *anthropicProvider) translateRequest(req *ChatRequest) *anthropicRequest {
	var system string
	var msgs []anthropicMessage

	for _, m := range req.Messages {
		if m.Role == "system" {
			if system != "" {
				system += "\n"
			}
			system += m.Content
			continue
		}

		// Tool-result messages map to Anthropic's user role with tool_result content blocks.
		if m.Role == "tool" && m.ToolCallID != "" {
			block := map[string]interface{}{
				"type":        "tool_result",
				"tool_use_id": m.ToolCallID,
				"content":     m.Content,
			}
			contentJSON, _ := json.Marshal([]interface{}{block})
			msgs = append(msgs, anthropicMessage{Role: "user", Content: contentJSON})
			continue
		}

		// Assistant messages with tool_calls: build content blocks with text + tool_use.
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			var blocks []interface{}
			if m.Content != "" {
				blocks = append(blocks, map[string]string{"type": "text", "text": m.Content})
			}
			var toolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			}
			if err := json.Unmarshal(m.ToolCalls, &toolCalls); err == nil {
				for _, tc := range toolCalls {
					var args json.RawMessage
					if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
						args = json.RawMessage(tc.Function.Arguments)
					}
					blocks = append(blocks, map[string]interface{}{
						"type":  "tool_use",
						"id":    tc.ID,
						"name":  tc.Function.Name,
						"input": args,
					})
				}
			}
			contentJSON, _ := json.Marshal(blocks)
			msgs = append(msgs, anthropicMessage{Role: "assistant", Content: contentJSON})
			continue
		}

		// Regular text message.
		contentJSON, _ := json.Marshal(m.Content)
		msgs = append(msgs, anthropicMessage{Role: m.Role, Content: contentJSON})
	}

	maxTokens := 4096
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		maxTokens = *req.MaxTokens
	}

	aReq := &anthropicRequest{
		Model:       p.model,
		Messages:    msgs,
		System:      system,
		MaxTokens:   maxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stop:        req.Stop,
	}

	// Pass through tools if present (Anthropic uses the same format for tools definitions).
	if len(req.Tools) > 0 {
		// OpenAI wraps each tool as {"type":"function","function":{...}}.
		// Anthropic expects {"name":...,"description":...,"input_schema":{...}}.
		var oaiTools []struct {
			Type     string `json:"type"`
			Function struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Parameters  json.RawMessage `json:"parameters"`
			} `json:"function"`
		}
		if err := json.Unmarshal(req.Tools, &oaiTools); err == nil {
			var aTools []map[string]interface{}
			for _, t := range oaiTools {
				aTools = append(aTools, map[string]interface{}{
					"name":         t.Function.Name,
					"description":  t.Function.Description,
					"input_schema": t.Function.Parameters,
				})
			}
			aReq.Tools, _ = json.Marshal(aTools)
		}
	}

	return aReq
}

func (p *anthropicProvider) translateResponse(aResp *anthropicResponse, modelAlias string) *ChatResponse {
	var textParts []string
	var toolCalls []map[string]interface{}

	for _, c := range aResp.Content {
		switch c.Type {
		case "text":
			textParts = append(textParts, c.Text)
		case "tool_use":
			argsJSON := string(c.Input)
			if argsJSON == "" {
				argsJSON = "{}"
			}
			toolCalls = append(toolCalls, map[string]interface{}{
				"id":   c.ID,
				"type": "function",
				"function": map[string]interface{}{
					"name":      c.Name,
					"arguments": argsJSON,
				},
			})
		}
	}

	content := strings.Join(textParts, "")
	finishReason := mapAnthropicStopReason(aResp.StopReason)

	msg := &ChatMessage{Role: "assistant", Content: content}
	if len(toolCalls) > 0 {
		msg.ToolCalls, _ = json.Marshal(toolCalls)
		if finishReason == "stop" {
			finishReason = "tool_calls"
		}
	}

	resp := &ChatResponse{
		ID:      "chatcmpl-" + strings.TrimPrefix(aResp.ID, "msg_"),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   modelAlias,
		Choices: []ChatChoice{{
			Index:        0,
			Message:      msg,
			FinishReason: &finishReason,
		}},
	}
	if aResp.Usage != nil {
		resp.Usage = &ChatUsage{
			PromptTokens:     aResp.Usage.InputTokens,
			CompletionTokens: aResp.Usage.OutputTokens,
			TotalTokens:      aResp.Usage.InputTokens + aResp.Usage.OutputTokens,
		}
	}
	return resp
}

func (p *anthropicProvider) readAnthropicSSE(r io.Reader, modelAlias string, cb func(StreamChunk)) (*ChatUsage, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	var msgID, model string
	var usage *ChatUsage
	created := time.Now().Unix()

	// Track current tool_use block for streaming tool call assembly.
	type pendingToolCall struct {
		Index int
		ID    string
		Name  string
		Args  strings.Builder
	}
	var toolCallIndex int
	var currentTool *pendingToolCall

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")

		var evt struct {
			Type         string          `json:"type"`
			Index        int             `json:"index"`
			Message      json.RawMessage `json:"message,omitempty"`
			Delta        json.RawMessage `json:"delta,omitempty"`
			ContentBlock json.RawMessage `json:"content_block,omitempty"`
			Usage        *anthropicUsage `json:"usage,omitempty"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue
		}

		switch evt.Type {
		case "message_start":
			var msgStart struct {
				ID    string `json:"id"`
				Model string `json:"model"`
			}
			if json.Unmarshal(evt.Message, &msgStart) == nil {
				msgID = "chatcmpl-" + strings.TrimPrefix(msgStart.ID, "msg_")
				model = modelAlias
			}
			role := "assistant"
			cb(StreamChunk{
				ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: role}}},
			})

		case "content_block_start":
			var block struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if json.Unmarshal(evt.ContentBlock, &block) == nil && block.Type == "tool_use" {
				currentTool = &pendingToolCall{
					Index: toolCallIndex,
					ID:    block.ID,
					Name:  block.Name,
				}
				toolCallIndex++
				// Emit the initial tool_call chunk with function name.
				tcJSON, _ := json.Marshal([]map[string]interface{}{{
					"index": currentTool.Index,
					"id":    currentTool.ID,
					"type":  "function",
					"function": map[string]interface{}{
						"name":      currentTool.Name,
						"arguments": "",
					},
				}})
				cb(StreamChunk{
					ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
					Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{ToolCalls: tcJSON}}},
				})
			}

		case "content_block_delta":
			var delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			}
			if json.Unmarshal(evt.Delta, &delta) == nil {
				if delta.Type == "text_delta" {
					cb(StreamChunk{
						ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
						Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: delta.Text}}},
					})
				} else if delta.Type == "input_json_delta" && currentTool != nil {
					currentTool.Args.WriteString(delta.PartialJSON)
					// Stream the argument fragment as a tool_call delta.
					tcJSON, _ := json.Marshal([]map[string]interface{}{{
						"index": currentTool.Index,
						"function": map[string]interface{}{
							"arguments": delta.PartialJSON,
						},
					}})
					cb(StreamChunk{
						ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
						Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{ToolCalls: tcJSON}}},
					})
				}
			}

		case "content_block_stop":
			currentTool = nil

		case "message_delta":
			var delta struct {
				StopReason string `json:"stop_reason"`
			}
			_ = json.Unmarshal(evt.Delta, &delta)
			fr := mapAnthropicStopReason(delta.StopReason)
			chunk := StreamChunk{
				ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &fr}},
			}
			if evt.Usage != nil {
				chunk.Usage = &ChatUsage{
					PromptTokens:     evt.Usage.InputTokens,
					CompletionTokens: evt.Usage.OutputTokens,
					TotalTokens:      evt.Usage.InputTokens + evt.Usage.OutputTokens,
				}
				usage = chunk.Usage
			}
			cb(chunk)

		case "message_stop":
			// handled by the caller after we return
		}
	}
	return usage, scanner.Err()
}

func mapAnthropicStopReason(reason string) string {
	switch reason {
	case "end_turn":
		return "stop"
	case "max_tokens":
		return "length"
	case "stop_sequence":
		return "stop"
	case "tool_use":
		return "tool_calls"
	default:
		if reason == "" {
			return "stop"
		}
		return reason
	}
}
