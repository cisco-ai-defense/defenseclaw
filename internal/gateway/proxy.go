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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

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

	primary          LLMProvider
	inspector        ContentInspector
	masterKey        string

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

	if cfg.Model == "" {
		return nil, fmt.Errorf("proxy: guardrail.model is required")
	}

	// Resolve the API key. Try .env first, then fall back to reading the key
	// directly from OpenClaw's auth-profiles.json (same source the fetch
	// interceptor uses). This ensures the primary provider works even before
	// OpenClaw is restarted to load the fetch interceptor plugin.
	apiKey := ResolveAPIKey(cfg.APIKeyEnv, dotenvPath)
	if apiKey == "" {
		apiKey = resolveKeyFromOpenClawProfiles(cfg.Model)
	}
	primary := NewProviderWithBase(cfg.Model, apiKey, cfg.APIBase)

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
		primary:      primary,
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

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// Extract text for inspection. Both OpenAI and Anthropic formats have a
	// top-level "messages" array — parse just enough to get the last user text.
	var partial struct {
		Messages []ChatMessage `json:"messages"`
		System   string        `json:"system,omitempty"`
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

	if userText != "" {
		t0 := time.Now()
		verdict := p.inspector.Inspect(r.Context(), "prompt", userText, partial.Messages, label, mode)
		elapsed := time.Since(t0)
		p.logPreCall(label, partial.Messages, verdict, elapsed)
		p.recordTelemetry("prompt", label, verdict, elapsed, nil, nil)
		if verdict.Action == "block" && mode == "action" {
			msg := blockMessage(customBlockMsg, "prompt", verdict.Reason)
			writeOpenAIError(w, http.StatusForbidden, msg)
			return
		}
	}

	// Forward verbatim to real upstream: reassemble original URL.
	upstreamURL := strings.TrimRight(targetOrigin, "/") + r.URL.RequestURI()
	fmt.Fprintf(os.Stderr, "[guardrail] → intercepted %s → %s\n", label, upstreamURL)
	upstreamKey := r.Header.Get("Authorization")

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamURL, bytes.NewReader(body))
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "failed to create upstream request: "+err.Error())
		return
	}

	// Copy all original headers except the ones specific to the proxy hop.
	for k, vs := range r.Header {
		switch strings.ToLower(k) {
		case "x-dc-target-url", "host":
			continue
		}
		for _, v := range vs {
			upstreamReq.Header.Add(k, v)
		}
	}
	if upstreamKey != "" {
		upstreamReq.Header.Set("Authorization", upstreamKey)
	}

	fmt.Fprintf(os.Stderr, "[guardrail] passthrough → %s\n", upstreamURL)
	resp, err := providerHTTPClient.Do(upstreamReq)
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "upstream error: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// Stream response back to caller.
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
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

// inferProviderFromURL maps a target URL (from the X-DC-Target-URL header
// set by the plugin's fetch interceptor) to a provider name. This is the
// most reliable routing signal when the fetch interceptor is active because
// it reflects the actual upstream the request was destined for.
func inferProviderFromURL(targetURL string) string {
	switch {
	case strings.Contains(targetURL, "anthropic.com"):
		return "anthropic"
	case strings.Contains(targetURL, "openrouter.ai"):
		return "openrouter"
	case strings.Contains(targetURL, "openai.com"):
		return "openai"
	case strings.Contains(targetURL, "googleapis.com"):
		return "gemini"
	case strings.Contains(targetURL, "amazonaws.com"):
		return "bedrock"
	case strings.Contains(targetURL, "openai.azure.com"):
		return "azure"
	default:
		return ""
	}
}

// resolveProvider selects the upstream LLMProvider for the given request.
// When X-DC-Target-URL is present (set by the plugin's fetch interceptor),
// it is used as the authoritative routing signal. Falls back to primary.
func (p *GuardrailProxy) resolveProvider(req *ChatRequest) LLMProvider {
	// Azure: detected via api-key header (req.TargetURL == "azure" sentinel).
	if req.TargetURL == "azure" {
		// Resolve base URL: .env → openclaw.json providers → default
		baseURL := ResolveAPIKey("AZURE_OPENAI_ENDPOINT", filepath.Join(p.dataDir, ".env"))
		if baseURL == "" {
			baseURL = resolveAzureEndpointFromOpenClaw()
		}
		if baseURL == "" {
			baseURL = "https://api.openai.azure.com"
		}
		return &azureOpenAIProvider{
			model:   req.Model,
			apiKey:  req.TargetAPIKey,
			baseURL: baseURL,
		}
	}

	// Fetch interceptor path: X-DC-Target-URL set by plugin.
	if req.TargetURL != "" {
		if prefix := inferProviderFromURL(req.TargetURL); prefix != "" {
			return NewProviderWithBase(prefix+"/"+req.Model, req.TargetAPIKey, "")
		}
	}

	// Real provider key passed through (not sk-dc-* master key).
	prefix, _ := splitModel(req.Model)
	if prefix != "" && req.TargetAPIKey != "" && !strings.HasPrefix(req.TargetAPIKey, "sk-dc-") {
		return NewProviderWithBase(req.Model, req.TargetAPIKey, "")
	}

	return p.primary
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

	// X-DC-Target-URL is set by the plugin's fetch interceptor and tells the
	// proxy the real upstream URL the request was originally destined for.
	req.TargetURL = r.Header.Get("X-DC-Target-URL")

	// Preserve the auth header so it can be forwarded to the upstream.
	// Azure uses "api-key" header; all others use "Authorization: Bearer".
	if azureKey := r.Header.Get("api-key"); azureKey != "" {
		req.TargetAPIKey = azureKey
		req.TargetURL = "azure" // signal azureProvider routing
	} else if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		req.TargetAPIKey = strings.TrimPrefix(auth, "Bearer ")
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
	upstream := p.resolveProvider(&req)
	if upstream == nil {
		provName, _ := splitModel(req.Model)
		msg := fmt.Sprintf("provider %q is not supported by DefenseClaw guardrail — traffic blocked", provName)
		if req.Stream {
			p.writeBlockedStream(w, req.Model, msg)
		} else {
			writeOpenAIError(w, http.StatusForbidden, msg)
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
	lastScanLen := 0
	const scanInterval = 500
	streamFinishReasons := []string{}

	usage, err := upstream.ChatCompletionStream(r.Context(), req, func(chunk StreamChunk) {
		chunk.Model = aliasModel

		// Accumulate content for post-stream inspection.
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta != nil {
			accumulated.WriteString(chunk.Choices[0].Delta.Content)
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
				// Stop sending chunks — the client will see a truncated stream.
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

// resolveAzureEndpointFromOpenClaw reads Azure base URLs from openclaw.json
// models.providers entries whose baseUrl contains "openai.azure.com".
func resolveAzureEndpointFromOpenClaw() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(home, ".openclaw", "openclaw.json"))
	if err != nil {
		return ""
	}
	var cfg struct {
		Models struct {
			Providers map[string]struct {
				BaseURL string `json:"baseUrl"`
			} `json:"providers"`
		} `json:"models"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	for _, prov := range cfg.Models.Providers {
		if strings.Contains(prov.BaseURL, "openai.azure.com") {
			return prov.BaseURL
		}
	}
	return ""
}

// resolveKeyFromOpenClawProfiles reads the API key for a given model's provider
// from OpenClaw's auth-profiles.json (~/.openclaw/agents/main/agent/auth-profiles.json).
// This is the same source the fetch interceptor uses, ensuring keys are always
// sourced from OpenClaw without needing a separate .env entry.
func resolveKeyFromOpenClawProfiles(model string) string {
	providerName, _ := splitModel(model)
	if providerName == "" {
		providerName = inferProvider(model, "")
	}
	profileID := providerName + ":default"

	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	profilesPath := filepath.Join(home, ".openclaw", "agents", "main", "agent", "auth-profiles.json")
	data, err := os.ReadFile(profilesPath)
	if err != nil {
		return ""
	}
	var profiles struct {
		Profiles map[string]struct {
			Key string `json:"key"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(data, &profiles); err != nil {
		return ""
	}
	if p, ok := profiles.Profiles[profileID]; ok && p.Key != "" {
		return p.Key
	}
	return ""
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
