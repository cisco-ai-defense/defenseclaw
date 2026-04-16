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

const ollamaBaseURL = "http://127.0.0.1:11434"

// ---------------------------------------------------------------------------
// Ollama provider — native Ollama /api/chat API
// ---------------------------------------------------------------------------

type ollamaProvider struct {
	model   string
	baseURL string
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	NumPredict  *int     `json:"num_predict,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
	Stop        []string `json:"stop,omitempty"`
}

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  *ollamaOptions  `json:"options,omitempty"`
}

type ollamaChatResponse struct {
	Model              string         `json:"model"`
	CreatedAt          string         `json:"created_at"`
	Message            *ollamaMessage `json:"message"`
	Done               bool           `json:"done"`
	DoneReason         string         `json:"done_reason"`
	PromptEvalCount    int64          `json:"prompt_eval_count"`
	EvalCount          int64          `json:"eval_count"`
	TotalDuration      int64          `json:"total_duration"`
	LoadDuration       int64          `json:"load_duration"`
	PromptEvalDuration int64          `json:"prompt_eval_duration"`
	EvalDuration       int64          `json:"eval_duration"`
}

func (p *ollamaProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	body, err := p.marshalRequest(req, false)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/api/chat", bytes.NewReader(body))
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
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("provider: read response: %w", err)
	}

	var ollamaResp ollamaChatResponse
	if err := json.Unmarshal(rawResp, &ollamaResp); err != nil {
		return nil, fmt.Errorf("provider: decode response: %w", err)
	}

	return translateOllamaResponse(&ollamaResp, p.model), nil
}

func (p *ollamaProvider) ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error) {
	body, err := p.marshalRequest(req, true)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/api/chat", bytes.NewReader(body))
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
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider: upstream returned %d: %s", resp.StatusCode, string(respBody))
	}

	return readOllamaStream(resp.Body, p.model, chunkCb)
}

func (p *ollamaProvider) marshalRequest(req *ChatRequest, stream bool) ([]byte, error) {
	msgs := make([]ollamaMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, ollamaMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	var options *ollamaOptions
	if req.MaxTokens != nil || req.Temperature != nil || req.TopP != nil || len(req.Stop) > 0 {
		options = &ollamaOptions{
			NumPredict:  req.MaxTokens,
			Temperature: req.Temperature,
			TopP:        req.TopP,
		}
		if len(req.Stop) > 0 {
			var stop []string
			if err := json.Unmarshal(req.Stop, &stop); err == nil && len(stop) > 0 {
				options.Stop = stop
			} else {
				var single string
				if err := json.Unmarshal(req.Stop, &single); err == nil && single != "" {
					options.Stop = []string{single}
				}
			}
		}
	}

	ollamaReq := ollamaChatRequest{
		Model:    p.model,
		Messages: msgs,
		Stream:   stream,
		Options:  options,
	}
	body, err := json.Marshal(ollamaReq)
	if err != nil {
		return nil, fmt.Errorf("provider: marshal request: %w", err)
	}
	return body, nil
}

func translateOllamaResponse(resp *ollamaChatResponse, model string) *ChatResponse {
	created := time.Now().Unix()
	if ts, err := time.Parse(time.RFC3339Nano, resp.CreatedAt); err == nil {
		created = ts.Unix()
	}
	content := ""
	if resp.Message != nil {
		content = resp.Message.Content
	}
	finishReason := "stop"
	if resp.DoneReason != "" {
		finishReason = resp.DoneReason
	}
	return &ChatResponse{
		ID:      fmt.Sprintf("ollama-%d", time.Now().UnixNano()),
		Object:  "chat.completion",
		Created: created,
		Model:   model,
		Choices: []ChatChoice{{
			Index: 0,
			Message: &ChatMessage{
				Role:    "assistant",
				Content: content,
			},
			FinishReason: &finishReason,
		}},
		Usage: &ChatUsage{
			PromptTokens:     resp.PromptEvalCount,
			CompletionTokens: resp.EvalCount,
			TotalTokens:      resp.PromptEvalCount + resp.EvalCount,
		},
	}
}

func readOllamaStream(r io.Reader, model string, cb func(StreamChunk)) (*ChatUsage, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var usage *ChatUsage
	created := time.Now().Unix()
	streamID := fmt.Sprintf("chatcmpl-ollama-%d", time.Now().UnixNano())

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var resp ollamaChatResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			return usage, fmt.Errorf("provider: decode ollama stream: %w", err)
		}
		if ts, err := time.Parse(time.RFC3339Nano, resp.CreatedAt); err == nil {
			created = ts.Unix()
		}

		content := ""
		if resp.Message != nil {
			content = resp.Message.Content
		}

		chunk := StreamChunk{
			ID:      streamID,
			Object:  "chat.completion.chunk",
			Created: created,
			Model:   model,
			Choices: []ChatChoice{{
				Index: 0,
				Delta: &ChatMessage{
					Role:    "assistant",
					Content: content,
				},
			}},
		}

		if resp.Done {
			finishReason := "stop"
			if resp.DoneReason != "" {
				finishReason = resp.DoneReason
			}
			chunk.Choices[0].FinishReason = &finishReason
			chunk.Usage = &ChatUsage{
				PromptTokens:     resp.PromptEvalCount,
				CompletionTokens: resp.EvalCount,
				TotalTokens:      resp.PromptEvalCount + resp.EvalCount,
			}
			usage = chunk.Usage
		}

		cb(chunk)
	}

	return usage, scanner.Err()
}
