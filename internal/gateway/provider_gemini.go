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
// Gemini native provider — translates between OpenAI format and Gemini's
// native generateContent / streamGenerateContent API.
// ---------------------------------------------------------------------------

// geminiDefaultBase is now DefaultGeminiBaseURL in constants.go

// --- Gemini API request types ---

type geminiRequest struct {
	Contents          []geminiContent   `json:"contents"`
	SystemInstruction *geminiContent    `json:"systemInstruction,omitempty"`
	GenerationConfig  *geminiGenConfig  `json:"generationConfig,omitempty"`
	Tools             []geminiTool      `json:"tools,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text             string              `json:"text,omitempty"`
	FunctionCall     *geminiFunctionCall `json:"functionCall,omitempty"`
	FunctionResponse *geminiFunctionResp `json:"functionResponse,omitempty"`
}

type geminiFunctionCall struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args,omitempty"`
}

type geminiFunctionResp struct {
	Name     string                 `json:"name"`
	Response map[string]interface{} `json:"response"`
}

type geminiGenConfig struct {
	MaxOutputTokens *int     `json:"maxOutputTokens,omitempty"`
	Temperature     *float64 `json:"temperature,omitempty"`
	TopP            *float64 `json:"topP,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

type geminiTool struct {
	FunctionDeclarations []geminiFuncDecl `json:"functionDeclarations,omitempty"`
}

type geminiFuncDecl struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// --- Gemini API response types ---

type geminiResponse struct {
	Candidates    []geminiCandidate `json:"candidates"`
	UsageMetadata *geminiUsage      `json:"usageMetadata,omitempty"`
}

type geminiCandidate struct {
	Content      *geminiContent `json:"content,omitempty"`
	FinishReason string         `json:"finishReason,omitempty"`
}

type geminiUsage struct {
	PromptTokenCount     int64 `json:"promptTokenCount"`
	CandidatesTokenCount int64 `json:"candidatesTokenCount"`
	TotalTokenCount      int64 `json:"totalTokenCount"`
}

// --- Provider struct ---

type geminiNativeProvider struct {
	model   string
	apiKey  string
	baseURL string
}

func (p *geminiNativeProvider) effectiveBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return DefaultGeminiBaseURL
}

func (p *geminiNativeProvider) generateURL(stream bool) string {
	base := p.effectiveBase()
	if stream {
		return fmt.Sprintf("%s/models/%s:streamGenerateContent?alt=sse&key=%s", base, p.model, p.apiKey)
	}
	return fmt.Sprintf("%s/models/%s:generateContent?key=%s", base, p.model, p.apiKey)
}

// --- LLMProvider interface ---

func (p *geminiNativeProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	gReq := translateGeminiRequest(req)

	body, err := json.Marshal(gReq)
	if err != nil {
		return nil, fmt.Errorf("provider: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.generateURL(false), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorResponseSize))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	var gResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&gResp); err != nil {
		return nil, fmt.Errorf("provider: decode response: %w", err)
	}

	return translateGeminiResponse(&gResp, req.Model), nil
}

func (p *geminiNativeProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
	gReq := translateGeminiRequest(req)

	body, err := json.Marshal(gReq)
	if err != nil {
		return nil, fmt.Errorf("provider: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.generateURL(true), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("provider: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider: stream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorResponseSize))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	return readGeminiSSE(resp.Body, req.Model, chunkCb)
}

// --- Translation functions ---

func translateGeminiRequest(req *ChatRequest) *geminiRequest {
	gReq := &geminiRequest{}

	// Collect system instructions and build contents.
	var systemParts []geminiPart
	var contents []geminiContent

	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			systemParts = append(systemParts, geminiPart{Text: m.Content})

		case "user":
			contents = append(contents, geminiContent{
				Role:  "user",
				Parts: []geminiPart{{Text: m.Content}},
			})

		case "assistant":
			// Check for tool_calls.
			if len(m.ToolCalls) > 0 {
				var parts []geminiPart
				if m.Content != "" {
					parts = append(parts, geminiPart{Text: m.Content})
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
						var args map[string]interface{}
						_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
						parts = append(parts, geminiPart{
							FunctionCall: &geminiFunctionCall{
								Name: tc.Function.Name,
								Args: args,
							},
						})
					}
				}
				contents = append(contents, geminiContent{Role: "model", Parts: parts})
			} else {
				contents = append(contents, geminiContent{
					Role:  "model",
					Parts: []geminiPart{{Text: m.Content}},
				})
			}

		case "tool":
			// Tool result messages map to Gemini's function role.
			var respData map[string]interface{}
			_ = json.Unmarshal([]byte(m.Content), &respData)
			if respData == nil {
				respData = map[string]interface{}{"result": m.Content}
			}
			name := m.Name
			if name == "" {
				name = "tool"
			}
			contents = append(contents, geminiContent{
				Role: "function",
				Parts: []geminiPart{{
					FunctionResponse: &geminiFunctionResp{
						Name:     name,
						Response: respData,
					},
				}},
			})
		}
	}

	if len(systemParts) > 0 {
		gReq.SystemInstruction = &geminiContent{Parts: systemParts}
	}
	gReq.Contents = contents

	// Generation config.
	var gc geminiGenConfig
	hasConfig := false
	if req.MaxTokens != nil {
		gc.MaxOutputTokens = req.MaxTokens
		hasConfig = true
	}
	if req.Temperature != nil {
		gc.Temperature = req.Temperature
		hasConfig = true
	}
	if req.TopP != nil {
		gc.TopP = req.TopP
		hasConfig = true
	}
	if len(req.Stop) > 0 {
		// Stop can be a string or array of strings.
		var stops []string
		if err := json.Unmarshal(req.Stop, &stops); err != nil {
			var single string
			if err2 := json.Unmarshal(req.Stop, &single); err2 == nil {
				stops = []string{single}
			}
		}
		if len(stops) > 0 {
			gc.StopSequences = stops
			hasConfig = true
		}
	}
	if hasConfig {
		gReq.GenerationConfig = &gc
	}

	// Tools.
	if len(req.Tools) > 0 {
		var oaiTools []struct {
			Type     string `json:"type"`
			Function struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Parameters  json.RawMessage `json:"parameters"`
			} `json:"function"`
		}
		if err := json.Unmarshal(req.Tools, &oaiTools); err == nil && len(oaiTools) > 0 {
			var decls []geminiFuncDecl
			for _, t := range oaiTools {
				decls = append(decls, geminiFuncDecl{
					Name:        t.Function.Name,
					Description: t.Function.Description,
					Parameters:  t.Function.Parameters,
				})
			}
			gReq.Tools = []geminiTool{{FunctionDeclarations: decls}}
		}
	}

	return gReq
}

func translateGeminiResponse(gResp *geminiResponse, modelAlias string) *ChatResponse {
	resp := &ChatResponse{
		ID:      "chatcmpl-gemini-" + fmt.Sprintf("%d", time.Now().UnixNano()),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   modelAlias,
	}

	for i, cand := range gResp.Candidates {
		var textParts []string
		var toolCalls []map[string]interface{}
		tcIndex := 0

		if cand.Content != nil {
			for _, part := range cand.Content.Parts {
				if part.Text != "" {
					textParts = append(textParts, part.Text)
				}
				if part.FunctionCall != nil {
					argsJSON, _ := json.Marshal(part.FunctionCall.Args)
					toolCalls = append(toolCalls, map[string]interface{}{
						"id":   fmt.Sprintf("call_%d_%d", i, tcIndex),
						"type": "function",
						"function": map[string]interface{}{
							"name":      part.FunctionCall.Name,
							"arguments": string(argsJSON),
						},
					})
					tcIndex++
				}
			}
		}

		content := strings.Join(textParts, "")
		fr := mapGeminiFinishReason(cand.FinishReason)

		msg := &ChatMessage{Role: "assistant", Content: content}
		if len(toolCalls) > 0 {
			msg.ToolCalls, _ = json.Marshal(toolCalls)
			if fr == "stop" {
				fr = "tool_calls"
			}
		}

		resp.Choices = append(resp.Choices, ChatChoice{
			Index:        i,
			Message:      msg,
			FinishReason: &fr,
		})
	}

	if gResp.UsageMetadata != nil {
		resp.Usage = &ChatUsage{
			PromptTokens:     gResp.UsageMetadata.PromptTokenCount,
			CompletionTokens: gResp.UsageMetadata.CandidatesTokenCount,
			TotalTokens:      gResp.UsageMetadata.TotalTokenCount,
		}
	}

	return resp
}

func readGeminiSSE(r io.Reader, modelAlias string, cb func(StreamChunk)) (*ChatUsage, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, SSEScannerBufferSize), SSEScannerMaxSize)
	var usage *ChatUsage
	created := time.Now().Unix()
	chunkID := "chatcmpl-gemini-stream"

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var gResp geminiResponse
		if err := json.Unmarshal([]byte(data), &gResp); err != nil {
			continue
		}

		// Process each candidate in the streamed response.
		for i, cand := range gResp.Candidates {
			if cand.Content != nil {
				for _, part := range cand.Content.Parts {
					if part.Text != "" {
						cb(StreamChunk{
							ID: chunkID, Object: "chat.completion.chunk", Created: created, Model: modelAlias,
							Choices: []ChatChoice{{Index: i, Delta: &ChatMessage{Content: part.Text}}},
						})
					}
					if part.FunctionCall != nil {
						argsJSON, _ := json.Marshal(part.FunctionCall.Args)
						tcJSON, _ := json.Marshal([]map[string]interface{}{{
							"index": 0,
							"id":    fmt.Sprintf("call_%d", i),
							"type":  "function",
							"function": map[string]interface{}{
								"name":      part.FunctionCall.Name,
								"arguments": string(argsJSON),
							},
						}})
						cb(StreamChunk{
							ID: chunkID, Object: "chat.completion.chunk", Created: created, Model: modelAlias,
							Choices: []ChatChoice{{Index: i, Delta: &ChatMessage{ToolCalls: tcJSON}}},
						})
					}
				}
			}

			// If finishReason is set, emit a final chunk.
			if cand.FinishReason != "" {
				fr := mapGeminiFinishReason(cand.FinishReason)
				cb(StreamChunk{
					ID: chunkID, Object: "chat.completion.chunk", Created: created, Model: modelAlias,
					Choices: []ChatChoice{{Index: i, Delta: &ChatMessage{}, FinishReason: &fr}},
				})
			}
		}

		// Track usage if present.
		if gResp.UsageMetadata != nil {
			usage = &ChatUsage{
				PromptTokens:     gResp.UsageMetadata.PromptTokenCount,
				CompletionTokens: gResp.UsageMetadata.CandidatesTokenCount,
				TotalTokens:      gResp.UsageMetadata.TotalTokenCount,
			}
		}
	}

	return usage, scanner.Err()
}

func mapGeminiFinishReason(reason string) string {
	switch reason {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY", "RECITATION":
		return "content_filter"
	default:
		return "stop"
	}
}
