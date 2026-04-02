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
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// guardrailListenAddr returns the TCP listen address for the guardrail HTTP server.
// Loopback-style hosts bind 127.0.0.1 only. Any other host (e.g. a veth / bridge
// IP for openshell standalone sandbox) binds that address so peers outside the
// host loopback namespace can connect — matching openclaw.json baseUrl from
// patch_openclaw_config.
func guardrailListenAddr(port int, effectiveHost string) string {
	h := strings.TrimSpace(effectiveHost)
	if h == "" {
		h = "localhost"
	}
	switch strings.ToLower(h) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return fmt.Sprintf("127.0.0.1:%d", port)
	default:
		return fmt.Sprintf("%s:%d", h, port)
	}
}

// ContentInspector abstracts guardrail inspection so the proxy can be
// tested with a mock inspector.
type ContentInspector interface {
	Inspect(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict
	SetScannerMode(mode string)
}

// GuardrailProxy is a pure Go LLM proxy that accepts OpenAI-compatible
// requests, runs guardrail inspection, and forwards to the upstream LLM
// provider.
type GuardrailProxy struct {
	cfg       *config.GuardrailConfig
	logger    *audit.Logger
	health    *SidecarHealth
	otel      *telemetry.Provider
	store     *audit.Store
	dataDir   string

	provider  LLMProvider
	inspector ContentInspector
	masterKey string

	// Runtime config protected by rtMu. The PATCH /v1/guardrail/config
	// endpoint on the API server writes guardrail_runtime.json; the proxy
	// reads it with a TTL cache.
	rtMu         sync.RWMutex
	mode         string
	blockMessage string
}

// NewGuardrailProxy constructs and wires a proxy. Returns an error if the
// upstream provider can't be resolved (missing model or API key).
func NewGuardrailProxy(
	cfg *config.GuardrailConfig,
	ciscoAID *config.CiscoAIDefenseConfig,
	logger *audit.Logger,
	health *SidecarHealth,
	otel *telemetry.Provider,
	store *audit.Store,
	dataDir string,
	policyDir string,
) (*GuardrailProxy, error) {
	dotenvPath := filepath.Join(dataDir, ".env")

	apiKey := ResolveAPIKey(cfg.APIKeyEnv, dotenvPath)
	if cfg.Model == "" {
		return nil, fmt.Errorf("proxy: guardrail.model is required")
	}
	if apiKey == "" && cfg.APIBase == "" {
		return nil, fmt.Errorf("proxy: no API key available (set guardrail.api_key_env and provide the key in ~/.defenseclaw/.env or environment)")
	}

	var provider LLMProvider
	if cfg.APIBase != "" {
		// Custom base URL — used for local model servers (Ollama) or proxied
		// providers where the upstream injects credentials.
		prov, modelID := splitModel(cfg.Model)
		if prov == "anthropic" || inferProvider(modelID, apiKey) == "anthropic" {
			provider = &anthropicProvider{model: modelID, apiKey: apiKey, baseURL: strings.TrimRight(cfg.APIBase, "/")}
		} else {
			provider = NewProviderWithBase(cfg.Model, apiKey, cfg.APIBase)
		}
	} else {
		var err error
		provider, err = NewProvider(cfg.Model, apiKey)
		if err != nil {
			return nil, fmt.Errorf("proxy: create provider: %w", err)
		}
	}

	var cisco *CiscoInspectClient
	if cfg.ScannerMode == "remote" || cfg.ScannerMode == "both" {
		cisco = NewCiscoInspectClient(ciscoAID, dotenvPath)
	}

	judge := NewLLMJudge(&cfg.Judge, dotenvPath)

	inspector := NewGuardrailInspector(cfg.ScannerMode, cisco, judge, policyDir)

	masterKey := deriveMasterKey(dataDir)

	return &GuardrailProxy{
		cfg:          cfg,
		logger:       logger,
		health:       health,
		otel:         otel,
		store:        store,
		dataDir:      dataDir,
		provider:     provider,
		inspector:    inspector,
		masterKey:    masterKey,
		mode:         cfg.Mode,
		blockMessage: cfg.BlockMessage,
	}, nil
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (p *GuardrailProxy) Run(ctx context.Context) error {
	if !p.cfg.Enabled {
		p.health.SetGuardrail(StateDisabled, "", nil)
		fmt.Fprintf(os.Stderr, "[guardrail] disabled (enable via: defenseclaw setup guardrail)\n")
		<-ctx.Done()
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", p.handleChatCompletion)
	mux.HandleFunc("/chat/completions", p.handleChatCompletion)
	mux.HandleFunc("/v1/messages", p.handleAnthropicMessages)
	mux.HandleFunc("/v1/models", p.handleModels)
	mux.HandleFunc("/models", p.handleModels)
	mux.HandleFunc("/health/liveliness", p.handleHealth)
	mux.HandleFunc("/health/readiness", p.handleHealth)
	mux.HandleFunc("/health", p.handleHealth)

	addr := guardrailListenAddr(p.cfg.Port, p.cfg.EffectiveHost())
	logged := p.requestLogger(mux)
	srv := &http.Server{Addr: addr, Handler: logged}

	p.health.SetGuardrail(StateStarting, "", map[string]interface{}{
		"port": p.cfg.Port,
		"mode": p.mode,
		"addr": addr,
	})
	fmt.Fprintf(os.Stderr, "[guardrail] starting proxy (addr=%s mode=%s model=%s)\n",
		addr, p.mode, p.cfg.ModelName)
	_ = p.logger.LogAction("guardrail-start", "",
		fmt.Sprintf("port=%d mode=%s model=%s", p.cfg.Port, p.mode, p.cfg.ModelName))

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	// Wait briefly for the server to bind, then mark healthy.
	select {
	case err := <-errCh:
		p.health.SetGuardrail(StateError, err.Error(), nil)
		return fmt.Errorf("proxy: listen %s: %w", addr, err)
	case <-time.After(200 * time.Millisecond):
		p.health.SetGuardrail(StateRunning, "", map[string]interface{}{
			"port": p.cfg.Port,
			"mode": p.mode,
			"addr": addr,
		})
		fmt.Fprintf(os.Stderr, "[guardrail] proxy ready on %s\n", addr)
		_ = p.logger.LogAction("guardrail-healthy", "", fmt.Sprintf("port=%d", p.cfg.Port))
	}

	select {
	case err := <-errCh:
		p.health.SetGuardrail(StateError, err.Error(), nil)
		return fmt.Errorf("proxy: server error: %w", err)
	case <-ctx.Done():
		p.health.SetGuardrail(StateStopped, "", nil)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

// requestLogger wraps a handler and logs every incoming request so we can
// diagnose 404s and unexpected paths from upstream callers.
func (p *GuardrailProxy) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(os.Stderr, "[guardrail] ← %s %s (from %s, content-length=%d)\n",
			r.Method, r.URL.Path, r.RemoteAddr, r.ContentLength)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if sw.status == http.StatusNotFound {
			fmt.Fprintf(os.Stderr, "[guardrail] 404 NOT FOUND: %s %s — no handler registered for this path\n",
				r.Method, r.URL.Path)
		}
	})
}

func (p *GuardrailProxy) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"healthy"}`))
}

// handleModels returns a minimal OpenAI-compatible /v1/models response.
// Some clients (including OpenClaw) probe this endpoint before sending
// chat completion requests.
func (p *GuardrailProxy) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.rtMu.RLock()
	modelName := p.cfg.ModelName
	if modelName == "" {
		modelName = p.cfg.Model
	}
	p.rtMu.RUnlock()

	resp := map[string]interface{}{
		"object": "list",
		"data": []map[string]interface{}{
			{
				"id":       modelName,
				"object":   "model",
				"owned_by": "defenseclaw",
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *GuardrailProxy) handleChatCompletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !p.authenticateRequest(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid API key","type":"authentication_error","code":"invalid_api_key"}}`))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	fmt.Fprintf(os.Stderr, "[guardrail] ── INCOMING REQUEST ──────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "[guardrail] raw body (%d bytes): %s\n", len(body), truncateLog(string(body), 2000))

	var req ChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] JSON parse error: %v\n", err)
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	req.RawBody = body

	fmt.Fprintf(os.Stderr, "[guardrail] parsed: model=%q stream=%v messages=%d\n",
		req.Model, req.Stream, len(req.Messages))

	if len(req.Messages) == 0 {
		writeOpenAIError(w, http.StatusBadRequest, "messages array is required and must not be empty")
		return
	}

	p.reloadRuntimeConfig()
	p.rtMu.RLock()
	mode := p.mode
	customBlockMsg := p.blockMessage
	p.rtMu.RUnlock()

	// --- Pre-call inspection ---
	userText := lastUserText(req.Messages)
	if userText != "" {
		t0 := time.Now()
		verdict := p.inspector.Inspect(r.Context(), "prompt", userText, req.Messages, req.Model, mode)
		elapsed := time.Since(t0)

		p.logPreCall(req.Model, req.Messages, verdict, elapsed)
		p.recordTelemetry("prompt", req.Model, verdict, elapsed, nil, nil)

		if verdict.Action == "block" && mode == "action" {
			msg := blockMessage(customBlockMsg, "prompt", verdict.Reason)
			if req.Stream {
				p.writeBlockedStream(w, req.Model, msg)
			} else {
				p.writeBlockedResponse(w, req.Model, msg)
			}
			return
		}
	}

	// --- Forward to upstream provider ---
	if req.Stream {
		p.handleStreamingRequest(w, r, &req, mode, customBlockMsg)
	} else {
		p.handleNonStreamingRequest(w, r, &req, mode, customBlockMsg)
	}
}

// ---------------------------------------------------------------------------
// Anthropic-native /v1/messages handler
// ---------------------------------------------------------------------------
// Accepts Anthropic Messages API format directly. Extracts text content from
// Anthropic's content block structure for scanner inspection, then forwards
// the original request body to the upstream untouched. Responses use
// RawResponse (non-streaming) or raw SSE forwarding (streaming).

// anthropicMessagesRequest is a minimal parse of the Anthropic Messages API
// request — just enough to extract scannable content and control flow.
type anthropicMessagesRequest struct {
	Model     string          `json:"model"`
	Messages  json.RawMessage `json:"messages"`
	System    json.RawMessage `json:"system,omitempty"`
	MaxTokens int             `json:"max_tokens"`
	Stream    bool            `json:"stream"`
}

// anthropicContentBlock represents a single block in an Anthropic message's
// content array. Different block types use different fields.
type anthropicContentBlock struct {
	Type    string          `json:"type"`
	Text    string          `json:"text,omitempty"`
	ID      string          `json:"id,omitempty"`
	Name    string          `json:"name,omitempty"`
	Input   json.RawMessage `json:"input,omitempty"`   // tool_use: function arguments
	Content json.RawMessage `json:"content,omitempty"` // tool_result: result content
}

// anthropicMessageItem is one message in the Anthropic messages array.
type anthropicMessageItem struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // string or []anthropicContentBlock
}

// extractAnthropicText walks Anthropic message content blocks and extracts
// all scannable text — plain text, tool inputs (JSON that could contain
// injections), and tool results.
func extractAnthropicText(msgs []anthropicMessageItem, system json.RawMessage) (userText string, allText string, chatMsgs []ChatMessage) {
	var sb strings.Builder
	var lastUser strings.Builder

	// System prompt
	if len(system) > 0 {
		var sysStr string
		if json.Unmarshal(system, &sysStr) == nil {
			sb.WriteString(sysStr)
			sb.WriteString("\n")
			chatMsgs = append(chatMsgs, ChatMessage{Role: "system", Content: sysStr})
		}
	}

	for _, msg := range msgs {
		var msgText strings.Builder

		// Content can be a plain string or an array of blocks.
		var plainStr string
		if json.Unmarshal(msg.Content, &plainStr) == nil {
			msgText.WriteString(plainStr)
		} else {
			var blocks []anthropicContentBlock
			if json.Unmarshal(msg.Content, &blocks) == nil {
				for _, block := range blocks {
					switch block.Type {
					case "text":
						msgText.WriteString(block.Text)
						msgText.WriteString("\n")
					case "tool_use":
						msgText.WriteString(string(block.Input))
						msgText.WriteString("\n")
					case "tool_result":
						// Tool results carry content in the "content" field.
						var resultText string
						if json.Unmarshal(block.Content, &resultText) == nil {
							msgText.WriteString(resultText)
						} else {
							msgText.WriteString(string(block.Content))
						}
						msgText.WriteString("\n")
					}
				}
			}
		}

		text := msgText.String()
		sb.WriteString(text)
		sb.WriteString("\n")
		chatMsgs = append(chatMsgs, ChatMessage{Role: msg.Role, Content: text})

		if msg.Role == "user" {
			lastUser.Reset()
			lastUser.WriteString(text)
		}
	}

	return strings.TrimSpace(lastUser.String()), strings.TrimSpace(sb.String()), chatMsgs
}

// writeAnthropicError writes a JSON error response in Anthropic's error format.
func writeAnthropicError(w http.ResponseWriter, status int, errType, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"type": "error",
		"error": map[string]string{
			"type":    errType,
			"message": msg,
		},
	})
}

func (p *GuardrailProxy) handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !p.authenticateRequest(r) {
		writeAnthropicError(w, http.StatusUnauthorized, "authentication_error", "invalid API key")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "failed to read request body")
		return
	}

	fmt.Fprintf(os.Stderr, "[guardrail] ← POST /v1/messages (%d bytes)\n", len(body))

	var antReq anthropicMessagesRequest
	if err := json.Unmarshal(body, &antReq); err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "invalid JSON body")
		return
	}

	var msgs []anthropicMessageItem
	if err := json.Unmarshal(antReq.Messages, &msgs); err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "invalid messages array")
		return
	}

	userText, _, chatMsgs := extractAnthropicText(msgs, antReq.System)

	p.reloadRuntimeConfig()
	p.rtMu.RLock()
	mode := p.mode
	customBlockMsg := p.blockMessage
	p.rtMu.RUnlock()

	// Pre-call inspection.
	if userText != "" {
		t0 := time.Now()
		verdict := p.inspector.Inspect(r.Context(), "prompt", userText, chatMsgs, antReq.Model, mode)
		elapsed := time.Since(t0)

		p.logPreCall(antReq.Model, chatMsgs, verdict, elapsed)
		p.recordTelemetry("prompt", antReq.Model, verdict, elapsed, nil, nil)

		if verdict.Action == "block" && mode == "action" {
			msg := blockMessage(customBlockMsg, "prompt", verdict.Reason)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":          "msg_blocked",
				"type":        "message",
				"role":        "assistant",
				"model":       antReq.Model,
				"content":     []map[string]string{{"type": "text", "text": msg}},
				"stop_reason": "end_turn",
			})
			return
		}
	}

	// Forward original request body to upstream untouched.
	prov, _ := p.provider.(*anthropicProvider)
	base := "https://api.anthropic.com"
	var apiKey string
	if prov != nil {
		if prov.baseURL != "" {
			base = prov.baseURL
		}
		apiKey = prov.apiKey
	}

	upstreamURL := base + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamURL, strings.NewReader(string(body)))
	if err != nil {
		writeAnthropicError(w, http.StatusInternalServerError, "api_error", "failed to create upstream request")
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("x-api-key", apiKey)
	}
	httpReq.Header.Set("anthropic-version", r.Header.Get("anthropic-version"))
	if httpReq.Header.Get("anthropic-version") == "" {
		httpReq.Header.Set("anthropic-version", "2023-06-01")
	}

	fmt.Fprintf(os.Stderr, "[guardrail] → upstream (Anthropic) model=%q stream=%v\n", antReq.Model, antReq.Stream)

	resp, err := providerHTTPClient.Do(httpReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] upstream error: %v\n", err)
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "upstream request failed")
		return
	}
	defer resp.Body.Close()

	if antReq.Stream {
		p.handleAnthropicStream(w, r, resp, antReq.Model, mode, customBlockMsg)
	} else {
		p.handleAnthropicNonStream(w, r, resp, antReq.Model, mode)
	}
}

func (p *GuardrailProxy) handleAnthropicNonStream(w http.ResponseWriter, r *http.Request, resp *http.Response, model, mode string) {
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "failed to read upstream response")
		return
	}

	// Extract text content from Anthropic response for post-call inspection.
	var antResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text,omitempty"`
		} `json:"content"`
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	var responseText strings.Builder
	if json.Unmarshal(respBody, &antResp) == nil {
		for _, block := range antResp.Content {
			if block.Type == "text" {
				responseText.WriteString(block.Text)
			}
		}
	}

	if responseText.Len() > 0 {
		content := responseText.String()
		t0 := time.Now()
		respMessages := []ChatMessage{{Role: "assistant", Content: content}}
		verdict := p.inspector.Inspect(r.Context(), "completion", content, respMessages, model, mode)
		elapsed := time.Since(t0)

		tokIn := antResp.Usage.InputTokens
		tokOut := antResp.Usage.OutputTokens
		p.logPostCall(model, content, verdict, elapsed, &ChatUsage{
			PromptTokens: tokIn, CompletionTokens: tokOut,
		})
		p.recordTelemetry("completion", model, verdict, elapsed, &tokIn, &tokOut)
	}

	// Write raw upstream response — Anthropic format preserved.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

func (p *GuardrailProxy) handleAnthropicStream(w http.ResponseWriter, r *http.Request, resp *http.Response, model, mode, customBlockMsg string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAnthropicError(w, http.StatusInternalServerError, "api_error", "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	var accumulated strings.Builder
	lastScanLen := 0
	const scanInterval = 500

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// Forward every line as-is (preserves event: and data: lines).
		fmt.Fprintf(w, "%s\n", line)
		if line == "" {
			flusher.Flush()
		}

		// Extract text content for inspection.
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			var evt struct {
				Type  string `json:"type"`
				Delta struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"delta"`
				Usage *struct {
					InputTokens  int64 `json:"input_tokens"`
					OutputTokens int64 `json:"output_tokens"`
				} `json:"usage"`
			}
			if json.Unmarshal([]byte(data), &evt) == nil {
				if evt.Type == "content_block_delta" && evt.Delta.Type == "text_delta" {
					accumulated.WriteString(evt.Delta.Text)
				}

				// Mid-stream inspection in action mode.
				if accumulated.Len()-lastScanLen >= scanInterval && mode == "action" {
					midVerdict := p.inspector.Inspect(r.Context(), "completion", accumulated.String(),
						[]ChatMessage{{Role: "assistant", Content: accumulated.String()}}, model, mode)
					if midVerdict.Severity != "NONE" && midVerdict.Action == "block" {
						fmt.Fprintf(os.Stderr, "[guardrail] STREAM-BLOCK severity=%s %s\n",
							midVerdict.Severity, midVerdict.Reason)
						p.recordTelemetry("completion", model, midVerdict, 0, nil, nil)
						return
					}
					lastScanLen = accumulated.Len()
				}
			}
		}
	}

	// Post-stream inspection.
	if accumulated.Len() > 0 {
		content := accumulated.String()
		t0 := time.Now()
		respMessages := []ChatMessage{{Role: "assistant", Content: content}}
		verdict := p.inspector.Inspect(r.Context(), "completion", content, respMessages, model, mode)
		elapsed := time.Since(t0)
		p.logPostCall(model, content, verdict, elapsed, nil)
		p.recordTelemetry("completion", model, verdict, elapsed, nil, nil)
	}
}

func (p *GuardrailProxy) handleNonStreamingRequest(w http.ResponseWriter, r *http.Request, req *ChatRequest, mode, customBlockMsg string) {
	aliasModel := req.Model
	fmt.Fprintf(os.Stderr, "[guardrail] → upstream (non-streaming) model=%q messages=%d\n", req.Model, len(req.Messages))
	resp, err := p.provider.ChatCompletion(r.Context(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] upstream error: %v\n", err)
		writeOpenAIError(w, http.StatusBadGateway, "upstream provider error: "+err.Error())
		return
	}
	resp.Model = aliasModel
	fmt.Fprintf(os.Stderr, "[guardrail] ← upstream response: choices=%d\n", len(resp.Choices))

	// --- Post-call inspection ---
	content := ""
	if len(resp.Choices) > 0 && resp.Choices[0].Message != nil {
		content = resp.Choices[0].Message.Content
	}

	if content != "" {
		t0 := time.Now()
		respMessages := []ChatMessage{{Role: "assistant", Content: content}}
		verdict := p.inspector.Inspect(r.Context(), "completion", content, respMessages, aliasModel, mode)
		elapsed := time.Since(t0)

		var tokIn, tokOut *int64
		if resp.Usage != nil {
			tokIn = &resp.Usage.PromptTokens
			tokOut = &resp.Usage.CompletionTokens
		}
		p.logPostCall(aliasModel, content, verdict, elapsed, resp.Usage)
		p.recordTelemetry("completion", aliasModel, verdict, elapsed, tokIn, tokOut)

		if verdict.Action == "block" && mode == "action" {
			msg := blockMessage(customBlockMsg, "completion", verdict.Reason)
			p.writeBlockedResponse(w, aliasModel, msg)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if len(resp.RawResponse) > 0 {
		patched, err := patchRawResponseModel(resp.RawResponse, aliasModel)
		if err == nil {
			_, _ = w.Write(patched)
			return
		}
		fmt.Fprintf(os.Stderr, "[guardrail] raw response patch failed, falling back to re-encode: %v\n", err)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *GuardrailProxy) handleStreamingRequest(w http.ResponseWriter, r *http.Request, req *ChatRequest, mode, customBlockMsg string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeOpenAIError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	aliasModel := req.Model
	fmt.Fprintf(os.Stderr, "[guardrail] → upstream (streaming) model=%q messages=%d\n", req.Model, len(req.Messages))
	var accumulated strings.Builder
	lastScanLen := 0
	const scanInterval = 500
	isRawPassthrough := false

	usage, err := p.provider.ChatCompletionStream(r.Context(), req, func(chunk StreamChunk) {
		chunk.Model = aliasModel
		if chunk.RawSSELine != "" {
			isRawPassthrough = true
		}

		// Accumulate content for post-stream inspection.
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta != nil {
			accumulated.WriteString(chunk.Choices[0].Delta.Content)
		}

		// Periodic mid-stream scan for streaming content.
		if accumulated.Len()-lastScanLen >= scanInterval && mode == "action" {
			midVerdict := p.inspector.Inspect(r.Context(), "completion", accumulated.String(),
				[]ChatMessage{{Role: "assistant", Content: accumulated.String()}}, aliasModel, mode)
			if midVerdict.Severity != "NONE" && midVerdict.Action == "block" {
				fmt.Fprintf(os.Stderr, "[guardrail] STREAM-BLOCK severity=%s %s\n",
					midVerdict.Severity, midVerdict.Reason)
				p.recordTelemetry("completion", aliasModel, midVerdict, 0, nil, nil)
				// Stop sending chunks — the client will see a truncated stream.
				return
			}
			lastScanLen = accumulated.Len()
		}

		if chunk.RawSSELine != "" {
			// Anthropic SSE passthrough — forward the original event format.
			fmt.Fprintf(w, "%s\n\n", chunk.RawSSELine)
		} else {
			data, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
		flusher.Flush()
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] stream error: %v\n", err)
	}

	// Final post-stream inspection.
	if accumulated.Len() > 0 {
		content := accumulated.String()
		t0 := time.Now()
		respMessages := []ChatMessage{{Role: "assistant", Content: content}}
		verdict := p.inspector.Inspect(r.Context(), "completion", content, respMessages, aliasModel, mode)
		elapsed := time.Since(t0)

		var tokIn, tokOut *int64
		if usage != nil {
			tokIn = &usage.PromptTokens
			tokOut = &usage.CompletionTokens
		}
		p.logPostCall(aliasModel, content, verdict, elapsed, &ChatUsage{
			PromptTokens: ptrOr(tokIn, 0), CompletionTokens: ptrOr(tokOut, 0),
		})
		p.recordTelemetry("completion", aliasModel, verdict, elapsed, tokIn, tokOut)
	}

	if !isRawPassthrough {
		fmt.Fprintf(w, "data: [DONE]\n\n")
	}
	flusher.Flush()
}

// ---------------------------------------------------------------------------
// Blocked response helpers
// ---------------------------------------------------------------------------

func (p *GuardrailProxy) writeBlockedResponse(w http.ResponseWriter, model, msg string) {
	finishReason := "stop"
	resp := ChatResponse{
		ID:      "chatcmpl-blocked",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []ChatChoice{{
			Index:        0,
			Message:      &ChatMessage{Role: "assistant", Content: msg},
			FinishReason: &finishReason,
		}},
		Usage: &ChatUsage{},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *GuardrailProxy) writeBlockedStream(w http.ResponseWriter, model, msg string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		p.writeBlockedResponse(w, model, msg)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	created := time.Now().Unix()
	id := "chatcmpl-blocked"

	// Initial chunk with role.
	role := "assistant"
	chunk0 := StreamChunk{
		ID: id, Object: "chat.completion.chunk", Created: created, Model: model,
		Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: role}}},
	}
	data0, _ := json.Marshal(chunk0)
	fmt.Fprintf(w, "data: %s\n\n", data0)
	flusher.Flush()

	// Content chunk.
	chunk1 := StreamChunk{
		ID: id, Object: "chat.completion.chunk", Created: created, Model: model,
		Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: msg}}},
	}
	data1, _ := json.Marshal(chunk1)
	fmt.Fprintf(w, "data: %s\n\n", data1)
	flusher.Flush()

	// Final chunk with finish_reason.
	fr := "stop"
	chunk2 := StreamChunk{
		ID: id, Object: "chat.completion.chunk", Created: created, Model: model,
		Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &fr}},
	}
	data2, _ := json.Marshal(chunk2)
	fmt.Fprintf(w, "data: %s\n\n", data2)
	flusher.Flush()

	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

func (p *GuardrailProxy) authenticateRequest(r *http.Request) bool {
	if p.masterKey == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ") == p.masterKey
	}
	return false
}

// deriveMasterKey produces a deterministic master key from the device key
// file, matching the legacy Python _derive_master_key().
func deriveMasterKey(dataDir string) string {
	keyFile := filepath.Join(dataDir, "device.key")
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, []byte("defenseclaw-proxy-master-key"))
	mac.Write(data)
	digest := fmt.Sprintf("%x", mac.Sum(nil))
	if len(digest) > 32 {
		digest = digest[:32]
	}
	return "sk-dc-" + digest
}

// ---------------------------------------------------------------------------
// Runtime config hot-reload
// ---------------------------------------------------------------------------

var (
	runtimeCacheMu sync.Mutex
	runtimeCache   map[string]string
	runtimeCacheTs time.Time
)

const runtimeCacheTTL = 5 * time.Second

func (p *GuardrailProxy) reloadRuntimeConfig() {
	runtimeCacheMu.Lock()
	defer runtimeCacheMu.Unlock()

	if time.Since(runtimeCacheTs) < runtimeCacheTTL && runtimeCache != nil {
		p.applyRuntime(runtimeCache)
		return
	}

	runtimeFile := filepath.Join(p.dataDir, "guardrail_runtime.json")
	data, err := os.ReadFile(runtimeFile)
	if err != nil {
		runtimeCache = nil
		runtimeCacheTs = time.Now()
		return
	}

	var cfg map[string]string
	if err := json.Unmarshal(data, &cfg); err != nil {
		runtimeCache = nil
		runtimeCacheTs = time.Now()
		return
	}

	runtimeCache = cfg
	runtimeCacheTs = time.Now()
	p.applyRuntime(cfg)
}

func (p *GuardrailProxy) applyRuntime(cfg map[string]string) {
	p.rtMu.Lock()
	defer p.rtMu.Unlock()

	if m, ok := cfg["mode"]; ok && (m == "observe" || m == "action") {
		p.mode = m
	}
	if sm, ok := cfg["scanner_mode"]; ok && (sm == "local" || sm == "remote" || sm == "both") {
		p.inspector.SetScannerMode(sm)
	}
	if bm, ok := cfg["block_message"]; ok {
		p.blockMessage = bm
	}
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

func (p *GuardrailProxy) logPreCall(model string, messages []ChatMessage, verdict *ScanVerdict, elapsed time.Duration) {
	ts := time.Now().UTC().Format("15:04:05")
	severity := verdict.Severity
	action := verdict.Action

	fmt.Fprintf(os.Stderr, "\n\033[1m\033[94m%s\033[0m\n", strings.Repeat("─", 60))
	fmt.Fprintf(os.Stderr, "\033[94m[%s]\033[0m \033[1mPRE-CALL\033[0m  model=%s  messages=%d  \033[2m%.0fms\033[0m\n",
		ts, model, len(messages), float64(elapsed.Milliseconds()))

	for i, msg := range messages {
		preview := truncateLog(msg.Content, 500)
		fmt.Fprintf(os.Stderr, "  \033[2m[%d]\033[0m %s (%d chars): %s\n", i, msg.Role, len(msg.Content), preview)
	}

	if severity == "NONE" {
		fmt.Fprintf(os.Stderr, "  verdict: \033[92m%s\033[0m\n", severity)
	} else {
		fmt.Fprintf(os.Stderr, "  verdict: \033[91m%s\033[0m  action=%s  %s\n", severity, action, verdict.Reason)
	}
	fmt.Fprintf(os.Stderr, "\033[94m%s\033[0m\n", strings.Repeat("─", 60))
}

func (p *GuardrailProxy) logPostCall(model, content string, verdict *ScanVerdict, elapsed time.Duration, usage *ChatUsage) {
	ts := time.Now().UTC().Format("15:04:05")
	severity := verdict.Severity
	action := verdict.Action

	fmt.Fprintf(os.Stderr, "\n\033[1m\033[92m%s\033[0m\n", strings.Repeat("─", 60))

	tokStr := ""
	if usage != nil {
		tokStr = fmt.Sprintf("  in=%d out=%d", usage.PromptTokens, usage.CompletionTokens)
	}
	fmt.Fprintf(os.Stderr, "\033[92m[%s]\033[0m \033[1mPOST-CALL\033[0m  model=%s%s  \033[2m%.0fms\033[0m\n",
		ts, model, tokStr, float64(elapsed.Milliseconds()))
	preview := truncateLog(content, 800)
	fmt.Fprintf(os.Stderr, "  response (%d chars): %s\n", len(content), preview)

	if severity == "NONE" {
		fmt.Fprintf(os.Stderr, "  verdict: \033[92m%s\033[0m\n", severity)
	} else {
		fmt.Fprintf(os.Stderr, "  verdict: \033[91m%s\033[0m  action=%s  %s\n", severity, action, verdict.Reason)
	}
	fmt.Fprintf(os.Stderr, "\033[92m%s\033[0m\n", strings.Repeat("─", 60))
}

func truncateLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + fmt.Sprintf("... (%d more chars)", len(s)-maxLen)
}

// patchRawResponseModel overwrites only the "model" field in raw JSON bytes,
// preserving all other upstream fields (system_fingerprint, service_tier, etc.).
func patchRawResponseModel(raw json.RawMessage, model string) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	modelBytes, _ := json.Marshal(model)
	m["model"] = modelBytes
	return json.Marshal(m)
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

func (p *GuardrailProxy) recordTelemetry(direction, model string, verdict *ScanVerdict, elapsed time.Duration, tokIn, tokOut *int64) {
	elapsedMs := float64(elapsed.Milliseconds())

	details := fmt.Sprintf("direction=%s action=%s severity=%s findings=%d elapsed_ms=%.1f",
		direction, verdict.Action, verdict.Severity, len(verdict.Findings), elapsedMs)
	if verdict.Reason != "" {
		reason := verdict.Reason
		if len(reason) > 120 {
			reason = reason[:120]
		}
		details += fmt.Sprintf(" reason=%s", reason)
	}

	if p.logger != nil {
		_ = p.logger.LogAction("guardrail-verdict", model, details)
	}
	if p.store != nil {
		evt := audit.Event{
			Action:    "guardrail-inspection",
			Target:    model,
			Severity:  verdict.Severity,
			Details:   details,
			Timestamp: time.Now().UTC(),
		}
		_ = p.store.LogEvent(evt)
	}

	if p.otel != nil {
		ctx := context.Background()
		p.otel.RecordGuardrailEvaluation(ctx, "guardrail-proxy", verdict.Action)
		p.otel.RecordGuardrailLatency(ctx, "guardrail-proxy", elapsedMs)
		if verdict.CiscoElapsedMs > 0 {
			p.otel.RecordGuardrailLatency(ctx, "cisco-ai-defense", verdict.CiscoElapsedMs)
			p.otel.RecordGuardrailEvaluation(ctx, "cisco-ai-defense", verdict.Action)
		}
		if tokIn != nil || tokOut != nil {
			p.otel.RecordLLMTokens(ctx, "guardrail-proxy", ptrOr(tokIn, 0), ptrOr(tokOut, 0))
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeOpenAIError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"message": msg,
			"type":    "invalid_request_error",
			"code":    "invalid_request",
		},
	})
}

func ptrOr(p *int64, def int64) int64 {
	if p != nil {
		return *p
	}
	return def
}
