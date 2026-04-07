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
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
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

	inspector        ContentInspector
	masterKey        string
	gatewayToken     string // OPENCLAW_GATEWAY_TOKEN, accepted in X-DC-Auth
	notify           *NotificationQueue

	// resolveProviderFn selects the upstream LLMProvider for a request.
	// Defaults to resolveProviderFromHeaders (uses X-DC-Target-URL).
	// Tests can override this to inject a mock provider.
	resolveProviderFn func(req *ChatRequest) LLMProvider

	// Runtime config protected by rtMu. The PATCH /v1/guardrail/config
	// endpoint on the API server writes guardrail_runtime.json; the proxy
	// reads it with a TTL cache.
	rtMu         sync.RWMutex
	mode         string
	blockMessage string
}

// NewGuardrailProxy constructs and wires a proxy. All provider routing is
// handled by the fetch interceptor's X-DC-Target-URL and X-AI-Auth headers.
func NewGuardrailProxy(
	cfg *config.GuardrailConfig,
	ciscoAID *config.CiscoAIDefenseConfig,
	logger *audit.Logger,
	health *SidecarHealth,
	otel *telemetry.Provider,
	store *audit.Store,
	dataDir string,
	policyDir string,
	notify *NotificationQueue,
) (*GuardrailProxy, error) {
	dotenvPath := filepath.Join(dataDir, ".env")

	var cisco *CiscoInspectClient
	if cfg.ScannerMode == "remote" || cfg.ScannerMode == "both" {
		cisco = NewCiscoInspectClient(ciscoAID, dotenvPath)
	}

	judge := NewLLMJudge(&cfg.Judge, dotenvPath)

	inspector := NewGuardrailInspector(cfg.ScannerMode, cisco, judge, policyDir)

	masterKey := deriveMasterKey(dataDir)
	gatewayToken := ResolveAPIKey("OPENCLAW_GATEWAY_TOKEN", dotenvPath)

	if gatewayToken == "" {
		fmt.Fprintf(os.Stderr, "[guardrail] WARNING: OPENCLAW_GATEWAY_TOKEN is not set — "+
			"loopback connections are trusted without authentication. Any local process "+
			"can relay requests through this proxy using forwarded API keys. "+
			"Set OPENCLAW_GATEWAY_TOKEN in ~/.defenseclaw/.env to require auth on all connections.\n")
	}

	p := &GuardrailProxy{
		cfg:          cfg,
		logger:       logger,
		health:       health,
		otel:         otel,
		store:        store,
		dataDir:      dataDir,
		inspector:    inspector,
		masterKey:    masterKey,
		gatewayToken: gatewayToken,
		notify:       notify,
		mode:         cfg.Mode,
		blockMessage: cfg.BlockMessage,
	}
	p.resolveProviderFn = p.resolveProviderFromHeaders
	return p, nil
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
	mux.HandleFunc("/v1/models", p.handleModels)
	mux.HandleFunc("/models", p.handleModels)
	mux.HandleFunc("/health/liveliness", p.handleHealth)
	mux.HandleFunc("/health/readiness", p.handleHealth)
	mux.HandleFunc("/health", p.handleHealth)
	// Catch-all for provider-native paths (e.g. /v1/messages for Anthropic,
	// /v1beta/models/*/generateContent for Gemini). The fetch interceptor
	// preserves the original path; we inspect the content then forward verbatim
	// to the real upstream from X-DC-Target-URL.
	mux.HandleFunc("/", p.handlePassthrough)

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

// handlePassthrough handles provider-native API paths (e.g. /v1/messages for
// Anthropic, /v1beta/models/*/generateContent for Gemini) that the fetch
// interceptor redirects to the proxy while preserving the original path.
//
// It extracts user-visible text for inspection, then forwards the entire
// original request body and headers verbatim to the real upstream URL
// (from X-DC-Target-URL + original path). No format translation is needed.
func (p *GuardrailProxy) handlePassthrough(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// GET on unknown paths (health probes, etc.) — just 200 OK.
		w.WriteHeader(http.StatusOK)
		return
	}
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

	// OpenAI-compatible paths (e.g. /api/v1/chat/completions from OpenRouter)
	// must use handleChatCompletion which has proper streaming SSE support.
	// Passthrough's io.Copy doesn't flush, breaking streaming responses.
	if strings.HasSuffix(r.URL.Path, "/chat/completions") {
		p.handleChatCompletion(w, r)
		return
	}

	targetOrigin := r.Header.Get("X-DC-Target-URL")
	if targetOrigin == "" {
		// No target URL — not from the fetch interceptor; reject.
		writeOpenAIError(w, http.StatusBadRequest, "missing X-DC-Target-URL header")
		return
	}

	// SSRF protection: only forward to domains listed in providers.json.
	// Reject requests targeting internal hosts (e.g. cloud IMDS, localhost).
	if !isKnownProviderDomain(targetOrigin) {
		fmt.Fprintf(os.Stderr, "[guardrail] BLOCKED passthrough to unknown domain: %s\n", targetOrigin)
		writeOpenAIError(w, http.StatusForbidden, "target URL does not match any known LLM provider domain")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// Extract text for inspection. Parse multiple API formats:
	//  - Chat Completions: {"messages": [...]}
	//  - Anthropic Messages: {"messages": [...], "system": "..."}
	//  - OpenAI/Azure Responses API: {"input": [...] | "string", "instructions": "..."}
	var partial struct {
		Model        string          `json:"model"`
		Messages     []ChatMessage   `json:"messages"`
		System       string          `json:"system,omitempty"`
		Instructions string          `json:"instructions,omitempty"` // Responses API system prompt
		Input        json.RawMessage `json:"input,omitempty"`         // Responses API
		Stream       bool            `json:"stream,omitempty"`
	}
	_ = json.Unmarshal(body, &partial)

	p.reloadRuntimeConfig()
	p.rtMu.RLock()
	mode := p.mode
	customBlockMsg := p.blockMessage
	p.rtMu.RUnlock()

	provider := inferProviderFromURL(targetOrigin)
	label := provider + r.URL.Path // e.g. "anthropic/v1/messages"

	userText := lastUserText(partial.Messages)
	if userText == "" && partial.System != "" {
		userText = partial.System
	}
	// Responses API: input can be a string or array of message/item objects.
	if userText == "" && len(partial.Input) > 0 {
		switch partial.Input[0] {
		case '"':
			// Plain string input
			_ = json.Unmarshal(partial.Input, &userText)
		case '[':
			// Array of items. The Responses API wraps each turn in an outer
			// object with "type":"message"; extract the inner content directly.
			var rawItems []json.RawMessage
			if json.Unmarshal(partial.Input, &rawItems) == nil {
				var inputMsgs []ChatMessage
				for _, raw := range rawItems {
					var wrapper struct {
						Type    string          `json:"type"`
						Role    string          `json:"role"`
						Content json.RawMessage `json:"content"`
					}
					if json.Unmarshal(raw, &wrapper) == nil {
						// Both bare messages and "type":"message" wrapped items.
						if wrapper.Role != "" {
							msg := ChatMessage{Role: wrapper.Role, RawContent: wrapper.Content}
							// Re-unmarshal to populate msg.Content via ChatMessage logic.
							_ = json.Unmarshal(raw, &msg)
							inputMsgs = append(inputMsgs, msg)
						}
					}
				}
				userText = lastUserText(inputMsgs)
				if len(partial.Messages) == 0 {
					partial.Messages = inputMsgs
				}
			}
		}
	}
	// Responses API: fall back to instructions (system-level prompt) if no
	// user turn was found — still worth inspecting for prompt injection.
	if userText == "" && partial.Instructions != "" {
		userText = partial.Instructions
	}

	if userText != "" {
		t0 := time.Now()
		verdict := p.inspector.Inspect(r.Context(), "prompt", userText, partial.Messages, label, mode)
		elapsed := time.Since(t0)
		p.logPreCall(label, partial.Messages, verdict, elapsed)
		p.recordTelemetry("prompt", label, verdict, elapsed, nil, nil)
		if verdict.Action == "block" && mode == "action" {
			msg := blockMessage(customBlockMsg, "prompt", verdict.Reason)
			// Return 200 with the block message as an assistant turn so
			// openclaw surfaces it to the user rather than treating it as
			// an error and retrying with a different provider.
			p.writeBlockedPassthrough(w, r.URL.Path, provider, partial.Model, partial.Stream, msg)
			return
		}
	}

	// Forward verbatim to real upstream: reassemble original URL.
	upstreamURL := strings.TrimRight(targetOrigin, "/") + r.URL.RequestURI()
	fmt.Fprintf(os.Stderr, "[guardrail] → intercepted %s → %s\n", label, scrubURLSecrets(upstreamURL))

	// Resolve the key to use for the upstream provider.
	// Priority: (1) X-AI-Auth from the fetch interceptor (normalized to
	// "Bearer <key>" regardless of the original header), (2) api-key (Azure),
	// (3) x-api-key (Anthropic), (4) Authorization — skipping sk-dc-* master keys.
	upstreamAuth := ""
	if aiAuth := r.Header.Get("X-AI-Auth"); aiAuth != "" && !strings.HasPrefix(aiAuth, "Bearer sk-dc-") {
		upstreamAuth = aiAuth
	}
	if upstreamAuth == "" {
		if azKey := r.Header.Get("api-key"); azKey != "" {
			upstreamAuth = "Bearer " + azKey
		} else if xKey := r.Header.Get("x-api-key"); xKey != "" {
			upstreamAuth = "Bearer " + xKey
		} else if auth := r.Header.Get("Authorization"); auth != "" && !strings.HasPrefix(auth, "Bearer sk-dc-") {
			upstreamAuth = auth
		}
	}

	// Apply a timeout so the proxy doesn't hang indefinitely if the upstream
	// provider stalls. Streaming responses may take longer, so use 5 minutes;
	// non-streaming gets 2 minutes (matching typical provider timeouts).
	passthroughTimeout := 2 * time.Minute
	if partial.Stream {
		passthroughTimeout = 5 * time.Minute
	}
	upstreamCtx, upstreamCancel := context.WithTimeout(r.Context(), passthroughTimeout)
	defer upstreamCancel()

	upstreamReq, err := http.NewRequestWithContext(upstreamCtx, http.MethodPost, upstreamURL, bytes.NewReader(body))
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "failed to create upstream request: "+err.Error())
		return
	}

	// Copy all original headers except proxy-hop and auth headers.
	// Auth headers (Authorization, x-api-key, api-key) are stripped to avoid
	// duplicates — the resolved upstreamAuth is set as the single canonical
	// Authorization header below.
	for k, vs := range r.Header {
		switch strings.ToLower(k) {
		case "x-dc-target-url", "x-ai-auth", "x-dc-auth", "host",
			"authorization", "x-api-key", "api-key":
			continue
		}
		for _, v := range vs {
			upstreamReq.Header.Add(k, v)
		}
	}
	// Set the single resolved auth header for the upstream provider.
	if upstreamAuth != "" {
		// Anthropic expects x-api-key, Azure expects api-key, others use Authorization.
		switch provider {
		case "anthropic":
			upstreamReq.Header.Set("x-api-key", strings.TrimPrefix(upstreamAuth, "Bearer "))
		case "azure":
			upstreamReq.Header.Set("api-key", strings.TrimPrefix(upstreamAuth, "Bearer "))
		default:
			upstreamReq.Header.Set("Authorization", upstreamAuth)
		}
	}

	fmt.Fprintf(os.Stderr, "[guardrail] passthrough → %s\n", scrubURLSecrets(upstreamURL))
	resp, err := providerHTTPClient.Do(upstreamReq)
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "upstream error: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// Determine whether the upstream response is streaming (SSE).
	isSSE := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")

	if !isSSE {
		// --- Non-streaming: buffer response, inspect, then forward ---
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		if readErr != nil {
			writeOpenAIError(w, http.StatusBadGateway, "failed to read upstream response")
			return
		}

		// Extract assistant text from provider-native response format.
		content := extractPassthroughResponseContent(respBody, provider)

		if content != "" {
			t0 := time.Now()
			respMessages := []ChatMessage{{Role: "assistant", Content: content}}
			verdict := p.inspector.Inspect(r.Context(), "completion", content, respMessages, label, mode)
			elapsed := time.Since(t0)
			p.logPostCall(label, content, verdict, elapsed, nil)
			p.recordTelemetry("completion", label, verdict, elapsed, nil, nil)

			if verdict.Action == "block" && mode == "action" {
				msg := blockMessage(customBlockMsg, "completion", verdict.Reason)
				p.writeBlockedPassthrough(w, r.URL.Path, provider, partial.Model, false, msg)
				return
			}
		}

		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
	} else {
		// --- Streaming: accumulate text from SSE chunks, periodic + final scan ---
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		flusher, _ := w.(http.Flusher)
		var accumulated strings.Builder
		lastScanLen := 0
		const scanInterval = 500
		buf := make([]byte, 4096)
		// lineBuf accumulates partial SSE lines across read boundaries.
		var lineBuf strings.Builder

		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				// Forward the raw bytes immediately so the client isn't stalled.
				_, _ = w.Write(chunk)
				if flusher != nil {
					flusher.Flush()
				}

				// Accumulate text from SSE data lines for inspection.
				lineBuf.Write(chunk)
				for {
					line, rest, found := strings.Cut(lineBuf.String(), "\n")
					if !found {
						break
					}
					lineBuf.Reset()
					lineBuf.WriteString(rest)

					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					data := strings.TrimPrefix(line, "data: ")
					if data == "[DONE]" {
						continue
					}
					text := extractSSEChunkText(data, provider)
					if text != "" {
						accumulated.WriteString(text)
					}
				}

				// Periodic mid-stream scan.
				if accumulated.Len()-lastScanLen >= scanInterval && mode == "action" {
					midVerdict := p.inspector.Inspect(r.Context(), "completion", accumulated.String(),
						[]ChatMessage{{Role: "assistant", Content: accumulated.String()}}, label, mode)
					if midVerdict.Severity != "NONE" && midVerdict.Action == "block" {
						fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-BLOCK severity=%s %s (WARNING: %d bytes already forwarded to client)\n",
							midVerdict.Severity, midVerdict.Reason, lastScanLen+len(chunk))
						p.recordTelemetry("completion", label, midVerdict, 0, nil, nil)
						break // stop forwarding; client sees truncated stream
					}
					lastScanLen = accumulated.Len()
				}
			}
			if readErr != nil {
				break
			}
		}

		// Final post-stream inspection on the full accumulated content.
		if accumulated.Len() > 0 {
			content := accumulated.String()
			t0 := time.Now()
			respMessages := []ChatMessage{{Role: "assistant", Content: content}}
			verdict := p.inspector.Inspect(r.Context(), "completion", content, respMessages, label, mode)
			elapsed := time.Since(t0)
			p.logPostCall(label, content, verdict, elapsed, nil)
			p.recordTelemetry("completion", label, verdict, elapsed, nil, nil)
			if verdict.Action == "block" {
				fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-VIOLATION severity=%s %s (stream already delivered %d bytes to client — cannot retract)\n",
					verdict.Severity, verdict.Reason, accumulated.Len())
			}
		}
	}
}

// extractPassthroughResponseContent extracts assistant text from a non-streaming
// provider-native response body. Supports Anthropic Messages API, Gemini, and
// OpenAI Responses API formats.
func extractPassthroughResponseContent(body []byte, provider string) string {
	switch provider {
	case "anthropic":
		// Anthropic: {"content": [{"type": "text", "text": "..."}]}
		var resp struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if json.Unmarshal(body, &resp) == nil {
			var sb strings.Builder
			for _, c := range resp.Content {
				if c.Type == "text" {
					sb.WriteString(c.Text)
				}
			}
			return sb.String()
		}

	case "gemini":
		// Gemini: {"candidates": [{"content": {"parts": [{"text": "..."}]}}]}
		var resp struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if json.Unmarshal(body, &resp) == nil {
			var sb strings.Builder
			for _, c := range resp.Candidates {
				for _, p := range c.Content.Parts {
					sb.WriteString(p.Text)
				}
			}
			return sb.String()
		}

	default:
		// OpenAI Responses API: {"output": [{"content": [{"text": "..."}]}]}
		var respAPI struct {
			Output []struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"output"`
		}
		if json.Unmarshal(body, &respAPI) == nil && len(respAPI.Output) > 0 {
			var sb strings.Builder
			for _, o := range respAPI.Output {
				for _, c := range o.Content {
					sb.WriteString(c.Text)
				}
			}
			if sb.Len() > 0 {
				return sb.String()
			}
		}

		// OpenAI Chat Completions: {"choices": [{"message": {"content": "..."}}]}
		var respCC struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if json.Unmarshal(body, &respCC) == nil && len(respCC.Choices) > 0 {
			return respCC.Choices[0].Message.Content
		}
	}
	return ""
}

// extractSSEChunkText extracts the assistant text delta from a single SSE
// data JSON object in a streaming provider-native response.
func extractSSEChunkText(data string, provider string) string {
	switch provider {
	case "anthropic":
		// Anthropic streaming: {"type":"content_block_delta","delta":{"type":"text_delta","text":"..."}}
		var chunk struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if json.Unmarshal([]byte(data), &chunk) == nil && chunk.Type == "content_block_delta" {
			return chunk.Delta.Text
		}

	case "gemini":
		// Gemini streaming: {"candidates":[{"content":{"parts":[{"text":"..."}]}}]}
		var chunk struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if json.Unmarshal([]byte(data), &chunk) == nil && len(chunk.Candidates) > 0 {
			var sb strings.Builder
			for _, p := range chunk.Candidates[0].Content.Parts {
				sb.WriteString(p.Text)
			}
			return sb.String()
		}

	default:
		// OpenAI Chat Completions streaming: {"choices":[{"delta":{"content":"..."}}]}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(data), &chunk) == nil && len(chunk.Choices) > 0 {
			return chunk.Choices[0].Delta.Content
		}
	}
	return ""
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

// providerDomains is built once at init from the embedded providers.json.
// Each entry maps a domain substring to the provider name.
var providerDomains []struct {
	domain string
	name   string
}

func init() {
	cfg, err := configs.LoadProviders()
	if err != nil {
		panic("gateway: failed to load embedded providers.json: " + err.Error())
	}
	for _, p := range cfg.Providers {
		for _, d := range p.Domains {
			providerDomains = append(providerDomains, struct {
				domain string
				name   string
			}{d, p.Name})
		}
	}
}

// inferProviderFromURL maps a target URL (from the X-DC-Target-URL header
// set by the plugin's fetch interceptor) to a provider name. The domain list
// is loaded from internal/configs/providers.json — the single source of truth
// shared with the TypeScript fetch interceptor.
func inferProviderFromURL(targetURL string) string {
	for _, pd := range providerDomains {
		if strings.Contains(targetURL, pd.domain) {
			return pd.name
		}
	}
	return ""
}

// resolveProviderFromHeaders selects the upstream LLMProvider for the given
// request. The fetch interceptor sets X-DC-Target-URL on every outbound LLM
// call; we infer the provider from that URL and use X-AI-Auth as the API key.
func (p *GuardrailProxy) resolveProviderFromHeaders(req *ChatRequest) LLMProvider {
	if req.TargetURL == "" {
		return nil
	}

	prefix := inferProviderFromURL(req.TargetURL)
	if prefix == "" {
		return nil
	}

	// Bedrock uses AWS Sigv4 authentication — it cannot be forwarded via the
	// Chat Completions translation path because the provider wrapper only
	// supports Bearer-token auth. Bedrock traffic must go through the
	// passthrough handler which preserves the original SDK-signed request.
	if prefix == "bedrock" {
		fmt.Fprintf(os.Stderr, "[guardrail] bedrock traffic must use passthrough — rejecting from chat completions handler\n")
		return nil
	}

	// Azure requires the specific resource endpoint as baseURL.
	baseURL := ""
	if prefix == "azure" {
		baseURL = req.TargetURL
	}

	return NewProviderWithBase(prefix+"/"+req.Model, req.TargetAPIKey, baseURL)
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
	fmt.Fprintf(os.Stderr, "[guardrail] headers: Authorization=%s api-key=%s X-DC-Target-URL=%s\n",
		truncateLog(r.Header.Get("Authorization"), 20),
		truncateLog(r.Header.Get("api-key"), 20),
		r.Header.Get("X-DC-Target-URL"))
	fmt.Fprintf(os.Stderr, "[guardrail] raw body (%d bytes): %s\n", len(body), truncateLog(string(body), 2000))

	var req ChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] JSON parse error: %v\n", err)
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	req.RawBody = body

	// X-DC-Target-URL is set by the plugin's fetch interceptor and tells the
	// proxy the real upstream URL the request was originally destined for.
	req.TargetURL = r.Header.Get("X-DC-Target-URL")

	// X-AI-Auth carries the real provider API key, normalized to
	// "Bearer <key>" by the fetch interceptor regardless of which header
	// the provider SDK originally used (Authorization, x-api-key, api-key).
	if aiAuth := r.Header.Get("X-AI-Auth"); strings.HasPrefix(aiAuth, "Bearer ") {
		req.TargetAPIKey = strings.TrimPrefix(aiAuth, "Bearer ")
	}

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

	// Hot-disabled: guardrail was turned off without sidecar restart.
	// Return 503 so the fetch interceptor stops routing through the proxy.
	if mode == "passthrough" {
		http.Error(w, `{"error":{"message":"DefenseClaw guardrail is disabled","code":"guardrail_disabled"}}`,
			http.StatusServiceUnavailable)
		return
	}

	// --- Inject pending security notifications as a system message ---
	if p.notify != nil {
		if sysMsg := p.notify.FormatSystemMessage(); sysMsg != "" {
			fmt.Fprintf(os.Stderr, "[guardrail] injecting security notification into LLM request\n")
			notification := ChatMessage{Role: "system", Content: sysMsg}
			req.Messages = append([]ChatMessage{notification}, req.Messages...)
			if len(req.RawBody) > 0 {
				if patched, err := injectSystemMessage(req.RawBody, sysMsg); err == nil {
					req.RawBody = patched
				}
			}
			if p.logger != nil {
				_ = p.logger.LogAction("guardrail-notify-inject", "", "injected security notification into LLM request")
			}
		}
	}

	// --- Create invoke_agent root span for this request ---
	var agentCtx context.Context
	var agentSpan trace.Span
	if p.otel != nil {
		conversationID := r.Header.Get("X-Conversation-ID")
		if conversationID == "" {
			conversationID = fmt.Sprintf("proxy-%d", time.Now().UnixNano())
		}
		agentCtx, agentSpan = p.otel.StartAgentSpan(
			context.Background(),
			conversationID, "openclaw", "",
		)
	}
	if agentCtx == nil {
		agentCtx = context.Background()
	}

	// --- Pre-call inspection (apply_guardrail input, child of invoke_agent) ---
	userText := lastUserText(req.Messages)
	if userText != "" {
		t0 := time.Now()

		// Start guardrail span for input inspection.
		var grSpan trace.Span
		if p.otel != nil {
			_, grSpan = p.otel.StartGuardrailSpan(
				agentCtx,
				"defenseclaw", "input", req.Model,
			)
		}

		verdict := p.inspector.Inspect(r.Context(), "prompt", userText, req.Messages, req.Model, mode)
		elapsed := time.Since(t0)

		// End guardrail span with decision.
		if p.otel != nil && grSpan != nil {
			decision := "allow"
			if verdict.Action == "block" {
				decision = "deny"
			} else if verdict.Severity != "NONE" {
				decision = "warn"
			}
			p.otel.EndGuardrailSpan(grSpan, decision, verdict.Severity, verdict.Reason, t0)
		}

		p.logPreCall(req.Model, req.Messages, verdict, elapsed)
		p.recordTelemetry("prompt", req.Model, verdict, elapsed, nil, nil)

		if verdict.Action == "block" && mode == "action" {
			if p.otel != nil && agentSpan != nil {
				p.otel.EndAgentSpan(agentSpan, "guardrail blocked")
			}
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
	if p.resolveProviderFn == nil {
		writeOpenAIError(w, http.StatusInternalServerError, "proxy misconfigured: no provider resolver")
		return
	}
	upstream := p.resolveProviderFn(&req)
	if upstream == nil {
		provName, _ := splitModel(req.Model)
		msg := fmt.Sprintf("provider %q is not supported by DefenseClaw guardrail — traffic blocked", provName)
		if req.Stream {
			p.writeBlockedStream(w, req.Model, msg)
		} else {
			p.writeBlockedResponse(w, req.Model, msg)
		}
		return
	}

	if req.Stream {
		p.handleStreamingRequest(w, r, &req, mode, customBlockMsg, upstream, agentCtx)
	} else {
		p.handleNonStreamingRequest(w, r, &req, mode, customBlockMsg, upstream, agentCtx)
	}

	// End invoke_agent span after the full request completes.
	if p.otel != nil && agentSpan != nil {
		p.otel.EndAgentSpan(agentSpan, "")
	}
}

func (p *GuardrailProxy) handleNonStreamingRequest(w http.ResponseWriter, r *http.Request, req *ChatRequest, mode, customBlockMsg string, upstream LLMProvider, agentCtx context.Context) {
	aliasModel := req.Model
	fmt.Fprintf(os.Stderr, "[guardrail] → upstream (non-streaming) model=%q messages=%d\n", req.Model, len(req.Messages))

	// Start LLM span as child of invoke_agent.
	llmStartTime := time.Now()
	system, providerName := p.llmSystemAndProvider(req.Model)
	maxTokens := 0
	if req.MaxTokens != nil {
		maxTokens = *req.MaxTokens
	}
	temperature := 0.0
	if req.Temperature != nil {
		temperature = *req.Temperature
	}
	var llmCtx context.Context
	var llmSpan trace.Span
	if p.otel != nil {
		llmCtx, llmSpan = p.otel.StartLLMSpan(
			agentCtx,
			system, aliasModel, providerName,
			maxTokens, temperature,
		)
	}

	resp, err := upstream.ChatCompletion(r.Context(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] upstream error: %v\n", err)
		if p.otel != nil && llmSpan != nil {
			p.otel.EndLLMSpan(llmSpan, aliasModel, 0, 0, []string{"error"}, 0, "none", "", system, llmStartTime, "openclaw")
		}
		writeOpenAIError(w, http.StatusBadGateway, "upstream provider error: "+err.Error())
		return
	}
	resp.Model = aliasModel
	fmt.Fprintf(os.Stderr, "[guardrail] ← upstream response: choices=%d\n", len(resp.Choices))

	// --- Post-call inspection (apply_guardrail output) ---
	content := ""
	finishReasons := []string{}
	toolCallCount := 0
	if len(resp.Choices) > 0 && resp.Choices[0].Message != nil {
		content = resp.Choices[0].Message.Content
		toolCallCount = countToolCalls(resp.Choices[0].Message.ToolCalls)
	}
	for _, c := range resp.Choices {
		if c.FinishReason != nil {
			finishReasons = append(finishReasons, *c.FinishReason)
		}
	}

	guardrail := "none"
	guardrailResult := ""

	if content != "" {
		t0 := time.Now()

		// Start guardrail span as child of the LLM span.
		var grSpan trace.Span
		if p.otel != nil {
			parentCtx := context.Background()
			if llmCtx != nil {
				parentCtx = llmCtx
			}
			_, grSpan = p.otel.StartGuardrailSpan(parentCtx, "defenseclaw", "output", aliasModel)
		}

		respMessages := []ChatMessage{{Role: "assistant", Content: content}}
		verdict := p.inspector.Inspect(r.Context(), "completion", content, respMessages, aliasModel, mode)
		elapsed := time.Since(t0)

		// End guardrail span with decision.
		if p.otel != nil && grSpan != nil {
			decision := "allow"
			if verdict.Action == "block" {
				decision = "deny"
			} else if verdict.Severity != "NONE" {
				decision = "warn"
			}
			p.otel.EndGuardrailSpan(grSpan, decision, verdict.Severity, verdict.Reason, t0)
		}

		var tokIn, tokOut *int64
		if resp.Usage != nil {
			tokIn = &resp.Usage.PromptTokens
			tokOut = &resp.Usage.CompletionTokens
		}
		p.logPostCall(aliasModel, content, verdict, elapsed, resp.Usage)
		p.recordTelemetry("completion", aliasModel, verdict, elapsed, tokIn, tokOut)

		if verdict.Severity != "NONE" {
			guardrail = "local"
			guardrailResult = verdict.Action
		}

		if verdict.Action == "block" && mode == "action" {
			if p.otel != nil && llmSpan != nil {
				promptTok, completionTok := 0, 0
				if resp.Usage != nil {
					promptTok = int(resp.Usage.PromptTokens)
					completionTok = int(resp.Usage.CompletionTokens)
				}
				p.otel.EndLLMSpan(llmSpan, aliasModel, promptTok, completionTok, finishReasons, toolCallCount, guardrail, "blocked", system, llmStartTime, "openclaw")
			}
			msg := blockMessage(customBlockMsg, "completion", verdict.Reason)
			p.writeBlockedResponse(w, aliasModel, msg)
			return
		}
	}

	// --- Post-call inspection: tool call arguments ---
	if len(resp.Choices) > 0 && resp.Choices[0].Message != nil {
		if verdict := p.inspectToolCalls(resp.Choices[0].Message.ToolCalls); verdict != nil {
			p.recordTelemetry("tool-call", aliasModel, verdict, 0, nil, nil)
			if verdict.Action == "block" && mode == "action" {
				if p.otel != nil && llmSpan != nil {
					p.otel.EndLLMSpan(llmSpan, aliasModel, 0, 0, finishReasons, toolCallCount, guardrail, guardrailResult, system, llmStartTime, "openclaw")
				}
				msg := blockMessage(customBlockMsg, "completion",
					fmt.Sprintf("tool call blocked — %s", verdict.Reason))
				p.writeBlockedResponse(w, aliasModel, msg)
				return
			}
		}
	}

	// --- Emit execute_tool spans for any tool_calls in the response ---
	if p.otel != nil && llmCtx != nil && len(resp.Choices) > 0 && resp.Choices[0].Message != nil {
		p.emitToolCallSpans(r.Context(), llmCtx, resp.Choices[0].Message.ToolCalls, aliasModel, mode)
	}

	// End LLM span with response data.
	if p.otel != nil && llmSpan != nil {
		promptTok, completionTok := 0, 0
		if resp.Usage != nil {
			promptTok = int(resp.Usage.PromptTokens)
			completionTok = int(resp.Usage.CompletionTokens)
		}
		p.otel.EndLLMSpan(llmSpan, aliasModel, promptTok, completionTok, finishReasons, toolCallCount, guardrail, guardrailResult, system, llmStartTime, "openclaw")
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

func (p *GuardrailProxy) handleStreamingRequest(w http.ResponseWriter, r *http.Request, req *ChatRequest, mode, customBlockMsg string, upstream LLMProvider, agentCtx context.Context) {
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

	// Start LLM span as child of invoke_agent.
	llmStartTime := time.Now()
	system, providerName := p.llmSystemAndProvider(req.Model)
	maxTokens := 0
	if req.MaxTokens != nil {
		maxTokens = *req.MaxTokens
	}
	temperature := 0.0
	if req.Temperature != nil {
		temperature = *req.Temperature
	}
	var llmSpan trace.Span
	if p.otel != nil {
		_, llmSpan = p.otel.StartLLMSpan(
			agentCtx,
			system, aliasModel, providerName,
			maxTokens, temperature,
		)
	}

	var accumulated strings.Builder
	var accToolCalls json.RawMessage
	lastScanLen := 0
	const scanInterval = 500
	streamFinishReasons := []string{}

	usage, err := upstream.ChatCompletionStream(r.Context(), req, func(chunk StreamChunk) {
		chunk.Model = aliasModel

		// Accumulate content and tool calls for post-stream inspection.
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta != nil {
			accumulated.WriteString(chunk.Choices[0].Delta.Content)
			if len(chunk.Choices[0].Delta.ToolCalls) > 0 {
				accToolCalls = mergeToolCallChunks(accToolCalls, chunk.Choices[0].Delta.ToolCalls)
			}
		}
		// Collect finish reasons from stream chunks.
		for _, c := range chunk.Choices {
			if c.FinishReason != nil && *c.FinishReason != "" {
				streamFinishReasons = append(streamFinishReasons, *c.FinishReason)
			}
		}

		// Periodic mid-stream scan for streaming content.
		if accumulated.Len()-lastScanLen >= scanInterval && mode == "action" {
			midVerdict := p.inspector.Inspect(r.Context(), "completion", accumulated.String(),
				[]ChatMessage{{Role: "assistant", Content: accumulated.String()}}, aliasModel, mode)
			if midVerdict.Severity != "NONE" && midVerdict.Action == "block" {
				fmt.Fprintf(os.Stderr, "[guardrail] STREAM-BLOCK severity=%s %s\n",
					midVerdict.Severity, midVerdict.Reason)
				p.recordTelemetry("completion", aliasModel, midVerdict, 0, nil, nil)
				return
			}
			lastScanLen = accumulated.Len()
		}

		data, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] stream error: %v\n", err)
		if p.otel != nil && llmSpan != nil {
			p.otel.EndLLMSpan(llmSpan, aliasModel, 0, 0, []string{"error"}, 0, "none", "", system, llmStartTime, "openclaw")
			llmSpan = nil
		}
	}

	guardrail := "none"
	guardrailResult := ""

	// Final post-stream inspection (apply_guardrail output).
	if accumulated.Len() > 0 {
		content := accumulated.String()
		t0 := time.Now()

		// Start guardrail span as child of the LLM span.
		var grSpan trace.Span
		if p.otel != nil {
			parentCtx := context.Background()
			if llmSpan != nil {
				// Use the span's context for proper hierarchy.
				parentCtx = trace.ContextWithSpan(context.Background(), llmSpan)
			}
			_, grSpan = p.otel.StartGuardrailSpan(parentCtx, "defenseclaw", "output", aliasModel)
		}

		respMessages := []ChatMessage{{Role: "assistant", Content: content}}
		verdict := p.inspector.Inspect(r.Context(), "completion", content, respMessages, aliasModel, mode)
		elapsed := time.Since(t0)

		// End guardrail span with decision.
		if p.otel != nil && grSpan != nil {
			decision := "allow"
			if verdict.Action == "block" {
				decision = "deny"
			} else if verdict.Severity != "NONE" {
				decision = "warn"
			}
			p.otel.EndGuardrailSpan(grSpan, decision, verdict.Severity, verdict.Reason, t0)
		}

		var tokIn, tokOut *int64
		if usage != nil {
			tokIn = &usage.PromptTokens
			tokOut = &usage.CompletionTokens
		}
		p.logPostCall(aliasModel, content, verdict, elapsed, &ChatUsage{
			PromptTokens: ptrOr(tokIn, 0), CompletionTokens: ptrOr(tokOut, 0),
		})
		p.recordTelemetry("completion", aliasModel, verdict, elapsed, tokIn, tokOut)

		if verdict.Severity != "NONE" {
			guardrail = "local"
			guardrailResult = verdict.Action
		}
	}

	// End LLM span with final data.
	if p.otel != nil && llmSpan != nil {
		promptTok, completionTok := 0, 0
		if usage != nil {
			promptTok = int(usage.PromptTokens)
			completionTok = int(usage.CompletionTokens)
		}
		p.otel.EndLLMSpan(llmSpan, aliasModel, promptTok, completionTok, streamFinishReasons, 0, guardrail, guardrailResult, system, llmStartTime, "openclaw")
	}

	// Final post-stream inspection: tool calls.
	if len(accToolCalls) > 0 {
		if verdict := p.inspectToolCalls(accToolCalls); verdict != nil {
			p.recordTelemetry("tool-call", aliasModel, verdict, 0, nil, nil)
		}
	}

	fmt.Fprintf(w, "data: [DONE]\n\n")
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

// writeBlockedPassthrough dispatches to the correct blocked-response writer
// based on provider, request path, and streaming flag. The response format
// must match the native API format of the original request so the caller
// can parse the blocked message instead of treating it as an error.
func (p *GuardrailProxy) writeBlockedPassthrough(w http.ResponseWriter, path, provider, model string, stream bool, msg string) {
	if provider == "anthropic" {
		if stream {
			p.writeBlockedStreamAnthropic(w, model, msg)
		} else {
			p.writeBlockedResponseAnthropic(w, model, msg)
		}
		return
	}
	if provider == "gemini" {
		// Gemini generateContent — return in Gemini-native format.
		p.writeBlockedResponseGemini(w, msg)
		return
	}
	// OpenAI Responses API (/v1/responses or /openai/v1/responses).
	if strings.HasSuffix(path, "/responses") {
		if stream {
			p.writeBlockedStreamOpenAIResponses(w, model, msg)
		} else {
			p.writeBlockedResponseOpenAIResponses(w, model, msg)
		}
		return
	}
	// Chat Completions API and all other OpenAI-compatible paths.
	if stream {
		p.writeBlockedStream(w, model, msg)
	} else {
		p.writeBlockedResponse(w, model, msg)
	}
}

// writeBlockedResponseGemini returns a blocked response in Gemini
// generateContent API format (non-streaming).
func (p *GuardrailProxy) writeBlockedResponseGemini(w http.ResponseWriter, msg string) {
	resp := map[string]interface{}{
		"candidates": []map[string]interface{}{{
			"content": map[string]interface{}{
				"parts": []map[string]interface{}{
					{"text": msg},
				},
				"role": "model",
			},
			"finishReason": "STOP",
			"index":        0,
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// writeBlockedResponseOpenAIResponses returns a blocked response in OpenAI
// Responses API format (non-streaming).
func (p *GuardrailProxy) writeBlockedResponseOpenAIResponses(w http.ResponseWriter, model, msg string) {
	resp := map[string]interface{}{
		"id":         "resp_blocked",
		"object":     "response",
		"created_at": time.Now().Unix(),
		"model":      model,
		"status":     "completed",
		"output": []map[string]interface{}{{
			"type":   "message",
			"id":     "msg_blocked",
			"role":   "assistant",
			"status": "completed",
			"content": []map[string]interface{}{{
				"type":        "output_text",
				"text":        msg,
				"annotations": []interface{}{},
			}},
		}},
		"usage": map[string]int{
			"input_tokens":  0,
			"output_tokens": 1,
			"total_tokens":  1,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// writeBlockedStreamOpenAIResponses returns a blocked response as an OpenAI
// Responses API server-sent event stream.
func (p *GuardrailProxy) writeBlockedStreamOpenAIResponses(w http.ResponseWriter, model, msg string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		p.writeBlockedResponseOpenAIResponses(w, model, msg)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	writeSSE := func(eventType string, data interface{}) {
		raw, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, raw)
		flusher.Flush()
	}

	respID := "resp_blocked"
	itemID := "item_blocked"

	writeSSE("response.created", map[string]interface{}{
		"type": "response.created",
		"response": map[string]interface{}{
			"id": respID, "object": "response", "model": model,
			"status": "in_progress", "output": []interface{}{},
		},
	})
	writeSSE("response.output_item.added", map[string]interface{}{
		"type":          "response.output_item.added",
		"response_id":   respID,
		"output_index":  0,
		"item": map[string]interface{}{
			"id": itemID, "type": "message", "role": "assistant",
			"status": "in_progress", "content": []interface{}{},
		},
	})
	writeSSE("response.content_part.added", map[string]interface{}{
		"type":          "response.content_part.added",
		"response_id":   respID,
		"item_id":       itemID,
		"output_index":  0,
		"content_index": 0,
		"part":          map[string]string{"type": "output_text", "text": ""},
	})
	writeSSE("response.output_text.delta", map[string]interface{}{
		"type":          "response.output_text.delta",
		"response_id":   respID,
		"item_id":       itemID,
		"output_index":  0,
		"content_index": 0,
		"delta":         msg,
	})
	writeSSE("response.output_text.done", map[string]interface{}{
		"type":          "response.output_text.done",
		"response_id":   respID,
		"item_id":       itemID,
		"output_index":  0,
		"content_index": 0,
		"text":          msg,
	})
	writeSSE("response.content_part.done", map[string]interface{}{
		"type":          "response.content_part.done",
		"response_id":   respID,
		"item_id":       itemID,
		"output_index":  0,
		"content_index": 0,
		"part": map[string]interface{}{
			"type": "output_text", "text": msg, "annotations": []interface{}{},
		},
	})
	writeSSE("response.output_item.done", map[string]interface{}{
		"type":         "response.output_item.done",
		"response_id":  respID,
		"output_index": 0,
		"item": map[string]interface{}{
			"id": itemID, "type": "message", "role": "assistant", "status": "completed",
			"content": []map[string]interface{}{{"type": "output_text", "text": msg, "annotations": []interface{}{}}},
		},
	})
	outputItem := map[string]interface{}{
		"id": itemID, "type": "message", "role": "assistant", "status": "completed",
		"content": []map[string]interface{}{{"type": "output_text", "text": msg, "annotations": []interface{}{}}},
	}
	writeSSE("response.completed", map[string]interface{}{
		"type": "response.completed",
		"response": map[string]interface{}{
			"id": respID, "object": "response", "model": model, "status": "completed",
			"output": []interface{}{outputItem},
			"usage":  map[string]int{"input_tokens": 0, "output_tokens": 1, "total_tokens": 1},
		},
	})
}

// writeBlockedResponseAnthropic returns a blocked response in Anthropic
// Messages API format (non-streaming).
func (p *GuardrailProxy) writeBlockedResponseAnthropic(w http.ResponseWriter, model, msg string) {
	resp := map[string]interface{}{
		"id":          "msg_blocked",
		"type":        "message",
		"role":        "assistant",
		"model":       model,
		"stop_reason": "end_turn",
		"content": []map[string]interface{}{
			{"type": "text", "text": msg},
		},
		"usage": map[string]int{"input_tokens": 0, "output_tokens": 1},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// writeBlockedStreamAnthropic returns a blocked response as an Anthropic
// Messages API SSE stream so the client receives a valid streaming response.
func (p *GuardrailProxy) writeBlockedStreamAnthropic(w http.ResponseWriter, model, msg string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		p.writeBlockedResponseAnthropic(w, model, msg)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	writeAnthropicSSE := func(eventType string, data interface{}) {
		raw, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, raw)
		flusher.Flush()
	}

	writeAnthropicSSE("message_start", map[string]interface{}{
		"type": "message_start",
		"message": map[string]interface{}{
			"id":      "msg_blocked",
			"type":    "message",
			"role":    "assistant",
			"model":   model,
			"content": []interface{}{},
			"usage":   map[string]int{"input_tokens": 0},
		},
	})
	writeAnthropicSSE("content_block_start", map[string]interface{}{
		"type":  "content_block_start",
		"index": 0,
		"content_block": map[string]string{
			"type": "text",
			"text": "",
		},
	})
	writeAnthropicSSE("ping", map[string]string{"type": "ping"})
	writeAnthropicSSE("content_block_delta", map[string]interface{}{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]string{
			"type": "text_delta",
			"text": msg,
		},
	})
	writeAnthropicSSE("content_block_stop", map[string]interface{}{
		"type":  "content_block_stop",
		"index": 0,
	})
	writeAnthropicSSE("message_delta", map[string]interface{}{
		"type": "message_delta",
		"delta": map[string]interface{}{
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
		},
		"usage": map[string]int{"output_tokens": 1},
	})
	writeAnthropicSSE("message_stop", map[string]string{"type": "message_stop"})
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
//
// Security boundary — the guardrail proxy forwards real LLM provider API keys
// (received via X-AI-Auth from the fetch interceptor) to upstream providers.
// This means any process that can reach the proxy can use those keys.
//
// Threat model:
//   - The proxy binds to 127.0.0.1 only, so remote hosts cannot connect.
//   - On loopback, ANY local process could reach this port.
//   - If gatewayToken is configured (OPENCLAW_GATEWAY_TOKEN), we require it on
//     ALL connections — including loopback — so that a rogue local process
//     cannot use the proxy as an open relay to LLM providers.
//   - If gatewayToken is NOT configured (legacy / first-run), loopback is
//     trusted unconditionally to avoid breaking existing setups. A warning is
//     logged at startup (see NewGuardrailProxy).
//   - For non-loopback (sandbox / bridge deployments), authentication is always
//     required via X-DC-Auth or the master key.

func (p *GuardrailProxy) authenticateRequest(r *http.Request) bool {
	isLoopback := strings.HasPrefix(r.RemoteAddr, "127.0.0.1:") || strings.HasPrefix(r.RemoteAddr, "[::1]:")

	// Check X-DC-Auth token (set by the fetch interceptor).
	if dcAuth := r.Header.Get("X-DC-Auth"); dcAuth != "" {
		token := strings.TrimPrefix(dcAuth, "Bearer ")
		if p.gatewayToken != "" && token == p.gatewayToken {
			return true
		}
	}

	// Check Authorization with the proxy master key.
	if p.masterKey != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") && strings.TrimPrefix(auth, "Bearer ") == p.masterKey {
			return true
		}
	}

	// Loopback fallback: allow when no gatewayToken is configured
	// (legacy / first-run). When a token exists, require it even on loopback
	// so rogue local processes cannot relay through the proxy.
	if isLoopback && p.gatewayToken == "" {
		return true
	}

	// No auth configured at all (neither gatewayToken nor masterKey) — the
	// proxy is open. This is the initial state before the user runs
	// `defenseclaw setup guardrail`. A startup warning is logged urging the
	// operator to set OPENCLAW_GATEWAY_TOKEN.
	if p.gatewayToken == "" && p.masterKey == "" {
		return true
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

// llmSystemAndProvider derives gen_ai.system and provider name from the model string.
// Reuses the router's inferSystem for consistency.
func (p *GuardrailProxy) llmSystemAndProvider(model string) (system, provider string) {
	parts := strings.SplitN(model, "/", 2)
	if len(parts) == 2 {
		provider = parts[0]
	}
	system = inferSystem(provider, model)
	if provider == "" {
		provider = system
	}
	return system, provider
}

func truncateLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + fmt.Sprintf("... (%d more chars)", len(s)-maxLen)
}

// scrubURLSecrets removes sensitive query parameters (key, api-key, apikey,
// token) from a URL string before logging.  Returns the original string
// unmodified when it contains no query string.
func scrubURLSecrets(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return raw
	}
	q := u.Query()
	for _, k := range []string{"key", "api-key", "apikey", "token"} {
		if q.Has(k) {
			q.Set(k, "REDACTED")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// isKnownProviderDomain returns true when the hostname of targetURL
// contains a domain substring from the embedded providers.json list.
// Only the parsed hostname is checked — query strings and path
// components are ignored to prevent bypass via crafted URLs like
// https://evil.com/?foo=api.openai.com.
func isKnownProviderDomain(targetURL string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	for _, pd := range providerDomains {
		if strings.Contains(host, pd.domain) {
			return true
		}
	}
	return false
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
			p.otel.RecordLLMTokens(ctx, "apply_guardrail", "defenseclaw", model, "openclaw", ptrOr(tokIn, 0), ptrOr(tokOut, 0))
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// injectSystemMessage prepends a system message to the "messages" array in
// the raw JSON body. This preserves all other fields the client sent.
func injectSystemMessage(raw json.RawMessage, content string) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("proxy: inject system message: unmarshal: %w", err)
	}

	msgBytes, ok := m["messages"]
	if !ok {
		return nil, fmt.Errorf("proxy: inject system message: no messages field")
	}

	var messages []json.RawMessage
	if err := json.Unmarshal(msgBytes, &messages); err != nil {
		return nil, fmt.Errorf("proxy: inject system message: unmarshal messages: %w", err)
	}

	sysMsg := ChatMessage{Role: "system", Content: content}
	sysMsgBytes, err := json.Marshal(sysMsg)
	if err != nil {
		return nil, fmt.Errorf("proxy: inject system message: marshal: %w", err)
	}

	messages = append([]json.RawMessage{sysMsgBytes}, messages...)
	newMsgBytes, err := json.Marshal(messages)
	if err != nil {
		return nil, fmt.Errorf("proxy: inject system message: marshal messages: %w", err)
	}
	m["messages"] = newMsgBytes
	return json.Marshal(m)
}

// ---------------------------------------------------------------------------
// Tool call inspection (defense-in-depth)
//
// When the LLM responds with tool_calls, inspect each tool's name and
// arguments with the same ScanAllRules engine used by the inspect endpoint.
// This catches dangerous tool calls (write_file with /etc/passwd, shell with
// reverse shells, etc.) even when the OpenClaw plugin is not loaded.
// ---------------------------------------------------------------------------

// inspectToolCalls scans tool call arguments in an OpenAI-format tool_calls
// JSON array. Returns a block verdict if any HIGH/CRITICAL findings, nil
// otherwise.
func (p *GuardrailProxy) inspectToolCalls(toolCallsJSON json.RawMessage) *ScanVerdict {
	if len(toolCallsJSON) == 0 {
		return nil
	}

	var toolCalls []struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(toolCallsJSON, &toolCalls); err != nil {
		return nil
	}

	var allFindings []RuleFinding
	for _, tc := range toolCalls {
		toolName := tc.Function.Name
		args := tc.Function.Arguments

		findings := ScanAllRules(args, toolName)
		allFindings = append(allFindings, findings...)
	}

	if len(allFindings) == 0 {
		return nil
	}

	severity := HighestSeverity(allFindings)
	confidence := HighestConfidence(allFindings, severity)

	action := "alert"
	if severity == "HIGH" || severity == "CRITICAL" {
		action = "block"
	}

	top := make([]string, 0, 5)
	for i, f := range allFindings {
		if i >= 5 {
			break
		}
		top = append(top, f.RuleID+":"+f.Title)
	}

	fmt.Fprintf(os.Stderr, "[guardrail] TOOL-CALL-INSPECT action=%s severity=%s findings=%d reason=%s\n",
		action, severity, len(allFindings), strings.Join(top, ", "))

	if p.logger != nil {
		for _, tc := range toolCalls {
			_ = p.logger.LogAction("guardrail-tool-call-inspect", tc.Function.Name,
				fmt.Sprintf("action=%s severity=%s confidence=%.2f", action, severity, confidence))
		}
	}

	if p.otel != nil {
		p.otel.RecordGuardrailEvaluation(context.Background(), "tool-call-inspect", action)
	}

	return &ScanVerdict{
		Action:         action,
		Severity:       severity,
		Reason:         strings.Join(top, ", "),
		Findings:       FindingStrings(allFindings),
		ScannerSources: []string{"tool-call-inspect"},
	}
}

// mergeToolCallChunks appends streaming tool_calls delta chunks into an
// accumulated JSON array. Streaming deltas arrive as partial arrays; we
// concatenate the raw JSON for post-stream inspection.
func mergeToolCallChunks(existing json.RawMessage, chunk json.RawMessage) json.RawMessage {
	if len(existing) == 0 {
		return chunk
	}
	return append(append(existing[:len(existing)-1], ','), chunk[1:]...)
}

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

// ---------------------------------------------------------------------------
// Tool call helpers for execute_tool spans
// ---------------------------------------------------------------------------

// toolCallEntry represents a single tool_call in an OpenAI response.
type toolCallEntry struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// countToolCalls returns the number of tool calls in a raw JSON array.
func countToolCalls(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var calls []toolCallEntry
	if err := json.Unmarshal(raw, &calls); err != nil {
		return 0
	}
	return len(calls)
}

// emitToolCallSpans creates execute_tool spans for each tool_call in the LLM
// response, as children of the chat span context. Each tool call is also
// inspected by the guardrail, producing a child apply_guardrail span.
func (p *GuardrailProxy) emitToolCallSpans(reqCtx, llmCtx context.Context, raw json.RawMessage, model, mode string) {
	if len(raw) == 0 {
		return
	}
	var calls []toolCallEntry
	if err := json.Unmarshal(raw, &calls); err != nil {
		return
	}
	for _, tc := range calls {
		name := tc.Function.Name
		if name == "" {
			name = "unknown"
		}
		toolCtx, span := p.otel.StartToolSpan(
			llmCtx, name, "pending", nil, false, "", "", "",
		)

		// --- Guardrail inspection of tool call arguments ---
		if toolCtx != nil && tc.Function.Arguments != "" {
			t0 := time.Now()
			_, grSpan := p.otel.StartGuardrailSpan(toolCtx, "defenseclaw", "tool_call", model)

			inspectContent := fmt.Sprintf("tool:%s args:%s", name, tc.Function.Arguments)
			msgs := []ChatMessage{{Role: "assistant", Content: inspectContent}}
			verdict := p.inspector.Inspect(reqCtx, "tool_call", inspectContent, msgs, model, mode)

			if grSpan != nil {
				decision := "allow"
				if verdict.Action == "block" {
					decision = "deny"
				} else if verdict.Severity != "NONE" {
					decision = "warn"
				}
				p.otel.EndGuardrailSpan(grSpan, decision, verdict.Severity, verdict.Reason, t0)
			}
		}

		p.otel.EndToolSpan(span, 0, 0, time.Now(), name, "")
	}
}
