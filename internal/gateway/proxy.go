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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/google/uuid"
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
	InspectMidStream(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict
	SetScannerMode(mode string)
}

// GuardrailProxy is a pure Go LLM proxy that accepts OpenAI-compatible
// requests, runs guardrail inspection, and forwards to the upstream LLM
// provider.
type GuardrailProxy struct {
	cfg     *config.GuardrailConfig
	logger  *audit.Logger
	health  *SidecarHealth
	otel    *telemetry.Provider
	store   *audit.Store
	dataDir string

	inspector    ContentInspector
	masterKey    string
	gatewayToken string // OPENCLAW_GATEWAY_TOKEN, accepted in X-DC-Auth
	notify       *NotificationQueue
	webhooks     *WebhookDispatcher

	// resolveProviderFn selects the upstream LLMProvider for a request.
	// Defaults to resolveProviderFromHeaders (uses X-DC-Target-URL).
	// Tests can override this to inject a mock provider.
	resolveProviderFn func(req *ChatRequest) LLMProvider

	// limiter caps the overall request rate to the proxy (all clients).
	// Defaults to 100 req/s with a burst of 200.
	limiter *rate.Limiter

	// Runtime config protected by rtMu. The PATCH /v1/guardrail/config
	// endpoint on the API server writes guardrail_runtime.json; the proxy
	// reads it with a TTL cache.
	rtMu         sync.RWMutex
	mode         string
	blockMessage string

	// Observability defaults set at bootstrap. defaultAgentName
	// falls back to cfg.Claw.Mode ("openclaw") when the request
	// does not carry an agent identifier; defaultPolicyID is the
	// active guardrail / admission policy identifier threaded into
	// tool and approval spans so per-policy aggregations in the
	// Splunk Local Bridge / AgentWatch summary work correctly.
	defaultAgentName string
	defaultPolicyID  string
}

// SetDefaultAgentName sets the agent name fallback for OTel spans when
// the request does not carry an identifier (e.g. cfg.Claw.Mode).
func (p *GuardrailProxy) SetDefaultAgentName(name string) {
	p.defaultAgentName = name
}

// SetDefaultPolicyID sets the active guardrail / admission policy id.
func (p *GuardrailProxy) SetDefaultPolicyID(id string) {
	p.defaultPolicyID = id
}

// agentNameForRequest picks the most specific agent name available.
// Stream-provided hints win over the router default.
func (p *GuardrailProxy) agentNameForRequest(hint string) string {
	if strings.TrimSpace(hint) != "" {
		return hint
	}
	return p.defaultAgentName
}

// agentIDForRequest returns the configured logical agent id for this
// sidecar (from the shared registry), or empty string when no agent id
// was configured. Used to label LLM metrics / spans with a deployment-
// bounded identifier so o11y dashboards can group by agent without
// relying on the free-text agent name.
func (p *GuardrailProxy) agentIDForRequest() string {
	return SharedAgentRegistry().AgentID()
}

// postCallContext returns a detached context for post-stream completion
// inspection. The HTTP request context may already be cancelled by the time
// the final POST-CALL inspection runs, which would kill in-flight LLM judge
// calls. We use context.WithoutCancel to preserve request-scoped values
// (tracing, correlation IDs) while disconnecting from the request lifecycle,
// then layer a timeout on top.
func (p *GuardrailProxy) postCallContext(parent context.Context) (context.Context, context.CancelFunc) {
	timeout := 30 * time.Second
	if p.cfg != nil && p.cfg.Judge.Timeout > 0 {
		timeout = time.Duration(p.cfg.Judge.Timeout * float64(time.Second))
	}
	detached := context.WithoutCancel(parent)
	return context.WithTimeout(detached, timeout)
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
	rp *guardrail.RulePack,
	judgeLLM config.LLMConfig,
) (*GuardrailProxy, error) {
	dotenvPath := filepath.Join(dataDir, ".env")

	var cisco *CiscoInspectClient
	if cfg.ScannerMode == "remote" || cfg.ScannerMode == "both" {
		cisco = NewCiscoInspectClient(ciscoAID, dotenvPath)
		if cisco != nil {
			cisco.SetTelemetry(otel)
		}
	}

	judge := NewLLMJudge(&cfg.Judge, judgeLLM, dotenvPath, rp)

	inspector := NewGuardrailInspector(cfg.ScannerMode, cisco, judge, policyDir)
	inspector.SetDetectionStrategy(
		cfg.DetectionStrategy,
		cfg.DetectionStrategyPrompt,
		cfg.DetectionStrategyCompletion,
		cfg.DetectionStrategyToolCall,
		cfg.JudgeSweep,
	)
	// Wire OTel span emission when telemetry is enabled. The
	// inspector only sees a closure, so the telemetry dep stays
	// localized to the proxy wiring layer.
	if otel != nil && otel.TracesEnabled() {
		inspector.SetTracerFunc(func(ctx context.Context, stage, direction, model string) (context.Context, func(action, severity, reason string, latencyMs int64)) {
			ctx, span := otel.StartGuardrailStageSpan(ctx, stage, direction, model)
			return ctx, func(action, severity, reason string, latencyMs int64) {
				otel.EndGuardrailStageSpan(span, action, severity, reason, latencyMs)
			}
		})
		// Phase 2: child spans for each sub-stage so operators can
		// drill into latency per phase (regex, cisco_ai_defense,
		// judge.*, opa) without sampling every span at the same depth.
		inspector.SetPhaseTracerFunc(func(ctx context.Context, phase string) (context.Context, func(action, severity string, latencyMs int64)) {
			ctx, span := otel.StartGuardrailPhaseSpan(ctx, phase)
			return ctx, func(action, severity string, latencyMs int64) {
				otel.EndGuardrailPhaseSpan(span, action, severity, latencyMs)
			}
		})
	}

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
		limiter:      rate.NewLimiter(rate.Limit(100), 200),
		mode:         cfg.Mode,
		blockMessage: cfg.BlockMessage,
	}
	p.resolveProviderFn = p.resolveProviderFromHeaders
	return p, nil
}

// SetWebhookDispatcher attaches a webhook dispatcher for guardrail block notifications.
func (p *GuardrailProxy) SetWebhookDispatcher(d *WebhookDispatcher) {
	p.webhooks = d
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
	mux.HandleFunc("/health/liveness", p.handleHealth)
	mux.HandleFunc("/health/liveliness", p.handleHealth) // backward compat
	mux.HandleFunc("/health/readiness", p.handleHealth)
	mux.HandleFunc("/health", p.handleHealth)
	// Catch-all for provider-native paths (e.g. /v1/messages for Anthropic,
	// /v1beta/models/*/generateContent for Gemini). The fetch interceptor
	// preserves the original path; we inspect the content then forward verbatim
	// to the real upstream from X-DC-Target-URL.
	mux.HandleFunc("/", p.handlePassthrough)

	addr := guardrailListenAddr(p.cfg.Port, p.cfg.EffectiveHost())
	InstallSharedAgentRegistry("", strings.TrimSpace(p.defaultAgentName))
	limited := p.rateLimitMiddleware(mux)
	logged := p.requestLogger(limited)
	withRequestID := p.requestIDMiddleware(logged)
	withCorr := CorrelationMiddleware(SharedAgentRegistry())(withRequestID)
	handler := otelHTTPServerMiddleware("guardrail-proxy", withCorr)
	srv := &http.Server{Addr: addr, Handler: handler}

	p.health.SetGuardrail(StateStarting, "", map[string]interface{}{
		"port": p.cfg.Port,
		"mode": p.mode,
		"addr": addr,
	})
	fmt.Fprintf(os.Stderr, "[guardrail] starting proxy (addr=%s mode=%s model=%s)\n",
		addr, p.mode, p.cfg.ModelName)
	_ = p.logger.LogAction("guardrail-start", "",
		fmt.Sprintf("port=%d mode=%s model=%s", p.cfg.Port, p.mode, p.cfg.ModelName))
	emitLifecycle(ctx, "guardrail", "start", map[string]string{
		"port":  fmt.Sprintf("%d", p.cfg.Port),
		"mode":  p.mode,
		"model": p.cfg.ModelName,
		"addr":  addr,
	})

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
		emitLifecycle(ctx, "guardrail", "ready", map[string]string{
			"port": fmt.Sprintf("%d", p.cfg.Port),
		})
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

// rateLimitMiddleware rejects requests that exceed the proxy-wide rate limit
// with HTTP 429 to prevent upstream provider saturation and LLM judge overload.
func (p *GuardrailProxy) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.limiter != nil && !p.limiter.Allow() {
			route := r.URL.Path
			if r.Pattern != "" {
				route = r.Pattern
			}
			if p.otel != nil {
				p.otel.RecordHTTPRateLimitBreach(r.Context(), route, "global")
			}
			w.Header().Set("Retry-After", "1")
			http.Error(w, `{"error":{"message":"rate limit exceeded","type":"rate_limit_error"}}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

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

	if !p.authenticateRequest(w, r) {
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

	// The fetch interceptor sets X-DC-Target-URL to the request origin only
	// (scheme://host). Rejoin the incoming request path so that path-prefixed
	// provider entries in providers.json (e.g. "chatgpt.com/backend-api") can
	// be matched correctly by the allowlist and the provider inference.
	targetForMatch := targetOrigin + r.URL.Path

	// SSRF protection: only forward to domains listed in providers.json
	// or Ollama loopback.  Reject other internal hosts (e.g. cloud IMDS).
	if !isKnownProviderDomain(targetForMatch) {
		fmt.Fprintf(os.Stderr, "[guardrail] BLOCKED passthrough to unknown domain: %s (path=%s)\n", targetOrigin, r.URL.Path)
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
		Input        json.RawMessage `json:"input,omitempty"`        // Responses API
		Stream       bool            `json:"stream,omitempty"`
	}
	_ = json.Unmarshal(body, &partial)

	p.reloadRuntimeConfig()
	p.rtMu.RLock()
	mode := p.mode
	customBlockMsg := p.blockMessage
	p.rtMu.RUnlock()

	provider := inferProviderFromURL(targetForMatch)
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

	if userText != "" && !isHeartbeatMessage(userText, partial.Messages) {
		t0 := time.Now()
		verdict := p.inspector.Inspect(r.Context(), "prompt", userText, partial.Messages, label, mode)
		elapsed := time.Since(t0)
		p.logPreCall(label, partial.Messages, verdict, elapsed)
		p.recordTelemetry(r.Context(), "prompt", label, verdict, elapsed, nil, nil)
		if verdict.Action == "block" && mode == "action" {
			msg := blockMessage(customBlockMsg, "prompt", verdict.Reason)
			// Enqueue a notification BEFORE writing the block
			// response so the next proxy call (this client's retry,
			// or any other session) carries the authoritative
			// `[DEFENSECLAW SECURITY ENFORCEMENT]` system message
			// via FormatSystemMessage. Without this, only the fake
			// assistant turn the client persists in its local
			// history informs the LLM — which is (a) client-dependent
			// and (b) semantically weaker than a system directive.
			p.enqueueBlockNotification(verdict, "prompt", partial.Model)
			// Return 200 with the block message as an assistant turn so
			// openclaw surfaces it to the user rather than treating it as
			// an error and retrying with a different provider.
			p.writeBlockedPassthrough(w, r.URL.Path, provider, partial.Model, partial.Stream, msg)
			return
		}
	}

	// --- Launder prior DefenseClaw-generated assistant turns ---
	//
	// When a previous turn was blocked, we returned a synthetic
	// assistant message starting with "[DefenseClaw] This request was
	// blocked…" as the *response*. OpenAI-compatible clients typically
	// persist that into their local conversation history and replay it
	// back at us on the next turn. That's a problem because:
	//   (a) the LLM sees its own prior "refusal" as immutable history
	//       and may keep reinforcing it instead of following the
	//       current system enforcement notice;
	//   (b) it makes the conversation look cluttered and confusing;
	//   (c) for OpenAI Responses API specifically, the persisted item
	//       has an `id` we don't control on subsequent turns — see the
	//       `msg_blocked` prefix fix in writeBlockedStreamOpenAIResponses.
	//
	// Strip them out before forwarding. The NotificationQueue (fed by
	// enqueueBlockNotification above) is the canonical channel for
	// informing the LLM about past enforcement actions, so we don't
	// lose any security context by dropping these echo turns.
	if launderedBody, stripped := launderInboundHistory(json.RawMessage(body), r.URL.Path); stripped > 0 {
		fmt.Fprintf(os.Stderr, "[guardrail] laundered %d DefenseClaw block turn(s) from passthrough history (path=%s)\n", stripped, r.URL.Path)
		body = []byte(launderedBody)
		if p.logger != nil {
			_ = p.logger.LogActionCtx(r.Context(), "guardrail-launder", r.URL.Path, fmt.Sprintf("stripped %d stale DefenseClaw block turn(s) from request history", stripped))
		}
	}

	// --- Inject pending security notifications as a system-level prompt ---
	//
	// Mirrors the handleChatCompletion injection site (search
	// "injecting security notification into LLM request"). Without this,
	// proxy-originated blocks (step 1) push notifications onto the queue
	// but the queue is only ever READ on the chat-completions code path,
	// meaning OpenAI Responses API clients (e.g. openai-codex via
	// chatgpt.com/backend-api/codex/responses) never see the enforcement
	// notice on the next turn. With this block, every supported provider
	// surface carries the notification forward as either a system
	// message or merged instructions string.
	if p.notify != nil {
		if sysMsg := p.notify.FormatSystemMessage(); sysMsg != "" {
			if patched, site, err := injectNotificationForPassthrough(json.RawMessage(body), sysMsg, r.URL.Path); err == nil {
				fmt.Fprintf(os.Stderr, "[guardrail] injecting security notification into passthrough request (site=%s path=%s)\n", site, r.URL.Path)
				body = []byte(patched)
				if p.logger != nil {
					_ = p.logger.LogActionCtx(r.Context(), "guardrail-notify-inject", site, "injected security notification into passthrough LLM request")
				}
			} else {
				// Not a failure: some provider surfaces (Anthropic,
				// Gemini) aren't wired for passthrough injection yet.
				// Log at debug-level stderr so operators notice drift
				// if a new provider appears, but never fail the
				// request just because injection didn't fit.
				fmt.Fprintf(os.Stderr, "[guardrail] passthrough notification injection skipped: %v\n", err)
			}
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
	// Pin ContentLength to the (possibly-mutated) body size so the Go
	// http client doesn't try to use the client-supplied length or fall
	// back to chunked encoding. Needed because notification injection
	// can change the body length; without this, some upstream providers
	// (notably Anthropic) reject the request with 400 "unexpected EOF".
	upstreamReq.ContentLength = int64(len(body))

	// Copy all original headers except proxy-hop and auth headers.
	// Auth headers (Authorization, x-api-key, api-key) are stripped to avoid
	// duplicates — the resolved upstreamAuth is set as the single canonical
	// Authorization header below. Content-Length is also stripped because
	// notification injection can change the body size; upstreamReq.ContentLength
	// is the authoritative value (set above) and the Go http client writes
	// the correct header automatically.
	for k, vs := range r.Header {
		switch strings.ToLower(k) {
		case "x-dc-target-url", "x-ai-auth", "x-dc-auth", "host",
			"authorization", "x-api-key", "api-key", "content-length":
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
			postCtx, postCancel := p.postCallContext(r.Context())
			t0 := time.Now()
			respMessages := []ChatMessage{{Role: "assistant", Content: content}}
			verdict := p.inspector.Inspect(postCtx, "completion", content, respMessages, label, mode)
			elapsed := time.Since(t0)
			postCancel()
			p.logPostCall(label, content, verdict, elapsed, nil)
			p.recordTelemetry(r.Context(), "completion", label, verdict, elapsed, nil, nil)

			if verdict.Action == "block" && mode == "action" {
				msg := blockMessage(customBlockMsg, "completion", verdict.Reason)
				p.enqueueBlockNotification(verdict, "completion", partial.Model)
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
		// --- Streaming: buffer initial bytes for pre-scan, then forward with periodic scans ---
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
		var lineBuf strings.Builder

		streamBufferSize := 1024
		if p.cfg != nil && p.cfg.StreamBufferBytes > 0 {
			streamBufferSize = p.cfg.StreamBufferBytes
		}
		const maxInitialBufBytes = 1 << 20 // 1 MiB cap on passthrough initial buffer
		var initialBuf []byte
		initialFlushed := mode != "action"
		preblocked := false
		flushInitialBuf := func() bool {
			if initialFlushed || len(initialBuf) == 0 {
				return true
			}
			if accumulated.Len() > 0 {
				initVerdict := p.inspector.InspectMidStream(r.Context(), "completion", accumulated.String(),
					[]ChatMessage{{Role: "assistant", Content: accumulated.String()}}, label, mode)
				if initVerdict.Severity != "NONE" && initVerdict.Action == "block" {
					fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-PREBLOCK severity=%s %s (blocked before any output sent to client)\n",
						initVerdict.Severity, redaction.Reason(initVerdict.Reason))
					p.recordTelemetry(r.Context(), "completion", label, initVerdict, 0, nil, nil)
					preblocked = true
					return false
				}
			}
			lastScanLen = accumulated.Len()
			_, _ = w.Write(initialBuf)
			if flusher != nil {
				flusher.Flush()
			}
			initialBuf = nil
			initialFlushed = true
			return true
		}

		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				chunk := buf[:n]

				// Parse SSE text for inspection regardless of buffer state.
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

				if !initialFlushed {
					initialBuf = append(initialBuf, chunk...)
					shouldFlush := accumulated.Len() >= streamBufferSize ||
						readErr != nil ||
						len(initialBuf) > maxInitialBufBytes

					if shouldFlush {
						if !flushInitialBuf() {
							break
						}
					}
				} else {
					_, _ = w.Write(chunk)
					if flusher != nil {
						flusher.Flush()
					}

					if accumulated.Len()-lastScanLen >= scanInterval && mode == "action" {
						midVerdict := p.inspector.InspectMidStream(r.Context(), "completion", accumulated.String(),
							[]ChatMessage{{Role: "assistant", Content: accumulated.String()}}, label, mode)
						if midVerdict.Severity != "NONE" && midVerdict.Action == "block" {
							fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-BLOCK severity=%s %s (WARNING: %d bytes already forwarded to client)\n",
								midVerdict.Severity, redaction.Reason(midVerdict.Reason), lastScanLen+len(chunk))
							p.recordTelemetry(r.Context(), "completion", label, midVerdict, 0, nil, nil)
							break
						}
						lastScanLen = accumulated.Len()
					}
				}
			}
			if readErr != nil {
				break
			}
		}
		if preblocked {
			return
		}
		if !initialFlushed && len(initialBuf) > 0 {
			if !flushInitialBuf() {
				return
			}
		}

		// Final post-stream inspection on the full accumulated content.
		// Use a detached context — the request context may be cancelled after streaming.
		if accumulated.Len() > 0 {
			content := accumulated.String()
			postCtx, postCancel := p.postCallContext(r.Context())
			t0 := time.Now()
			respMessages := []ChatMessage{{Role: "assistant", Content: content}}
			verdict := p.inspector.Inspect(postCtx, "completion", content, respMessages, label, mode)
			elapsed := time.Since(t0)
			postCancel()
			p.logPostCall(label, content, verdict, elapsed, nil)
			p.recordTelemetry(r.Context(), "completion", label, verdict, elapsed, nil, nil)
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

// ollamaPorts lists the TCP ports that Ollama binds to (from providers.json).
// Requests to localhost/127.0.0.1/::1 on these ports are treated as known
// provider traffic so the SSRF allowlist does not reject them.
var ollamaPorts []int

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
	ollamaPorts = cfg.OllamaPorts
}

// inferProviderFromURL maps a target URL (from the X-DC-Target-URL header
// set by the plugin's fetch interceptor) to a provider name. The domain list
// is loaded from internal/configs/providers.json — the single source of truth
// shared with the TypeScript fetch interceptor.
func inferProviderFromURL(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	for _, pd := range providerDomains {
		if matchProviderDomain(host, u.Path, pd.domain) {
			return pd.name
		}
	}
	if isOllamaLoopback(targetURL, 0) {
		return "ollama"
	}
	return ""
}

// resolveConfiguredProvider returns an LLMProvider using the guardrail config's
// model and API key. This handles the direct-provider case where OpenClaw is
// configured with "defenseclaw" as a custom provider and sends requests straight
// to the guardrail proxy without the fetch interceptor setting X-DC-Target-URL.
func (p *GuardrailProxy) resolveConfiguredProvider(req *ChatRequest) LLMProvider {
	cfgModel := p.cfg.Model
	if cfgModel == "" {
		fmt.Fprintf(os.Stderr, "[guardrail] no X-DC-Target-URL and no configured model — cannot route\n")
		return nil
	}

	apiKey := ""
	if req.TargetAPIKey != "" {
		apiKey = req.TargetAPIKey
	} else if p.cfg.APIKeyEnv != "" {
		dotenvPath := filepath.Join(p.dataDir, ".env")
		apiKey = ResolveAPIKey(p.cfg.APIKeyEnv, dotenvPath)
	}

	if apiKey == "" {
		fmt.Fprintf(os.Stderr, "[guardrail] no API key available for configured model %q\n", cfgModel)
		return nil
	}

	fmt.Fprintf(os.Stderr, "[guardrail] direct-provider mode: using configured model %q\n", cfgModel)

	provider, err := NewProvider(cfgModel, apiKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] failed to create provider for %q: %v\n", cfgModel, err)
		return nil
	}
	return provider
}

// resolveProviderFromHeaders selects the upstream LLMProvider for the given
// request. The fetch interceptor sets X-DC-Target-URL on every outbound LLM
// call; we infer the provider from that URL and use X-AI-Auth as the API key.
//
// Fallback: when X-DC-Target-URL is absent (direct-provider mode, where
// OpenClaw routes to the guardrail proxy as a custom provider endpoint), use
// the configured guardrail model and API key.
func (p *GuardrailProxy) resolveProviderFromHeaders(req *ChatRequest) LLMProvider {
	if req.TargetURL == "" {
		return p.resolveConfiguredProvider(req)
	}

	prefix := inferProviderFromURL(req.TargetURL + req.TargetPath)
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

	provider, err := NewProviderWithBase(prefix+"/"+req.Model, req.TargetAPIKey, baseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] provider error: %v\n", err)
		return nil
	}
	return provider
}

func (p *GuardrailProxy) handleChatCompletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !p.authenticateRequest(w, r) {
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
	// The raw LLM request body frequently contains user prompts
	// (SSNs, emails, passwords, API keys). Stderr is operator-
	// facing, so we honor DEFENSECLAW_REVEAL_PII via
	// redaction.MessageContent: set DEFENSECLAW_REVEAL_PII=1 to
	// get the raw body back for live debugging. Every persistent
	// sink (audit store, webhooks, OTel) already redacts further
	// downstream and never consults this flag.
	fmt.Fprintf(os.Stderr, "[guardrail] raw body (%d bytes): %s\n",
		len(body), truncateLog(redaction.MessageContent(string(body)), 2000))

	var req ChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] JSON parse error: %v\n", err)
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	req.RawBody = body

	// X-DC-Target-URL is set by the plugin's fetch interceptor and tells the
	// proxy the real upstream URL the request was originally destined for.
	// The header carries the origin only (scheme://host); the path arrives on
	// the incoming request URL. Keep them separate so Azure baseURL selection
	// below keeps working, but combine them for provider inference.
	req.TargetURL = r.Header.Get("X-DC-Target-URL")
	req.TargetPath = r.URL.Path

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

	// --- Launder prior DefenseClaw-generated assistant turns ---
	//
	// See launderInboundHistory in handlePassthrough for the full
	// rationale. Chat Completions clients (e.g. the LiteLLM bridge,
	// openclaw plugins) hit this code path, and they suffer the same
	// "replay stale refusal" pollution problem as Responses API clients.
	// Keep the mutation in lockstep so Chat Completions and Responses
	// API callers both get the cleanup.
	if len(req.RawBody) > 0 {
		if launderedBody, stripped := launderInboundHistory(req.RawBody, r.URL.Path); stripped > 0 {
			fmt.Fprintf(os.Stderr, "[guardrail] laundered %d DefenseClaw block turn(s) from chat-completions history\n", stripped)
			req.RawBody = launderedBody
			// Rebuild req.Messages from the laundered body so the
			// structured-path fallback stays consistent with RawBody.
			// Safe to ignore the error: if laundering produced valid
			// JSON, re-parsing it back will too.
			var rebuilt struct {
				Messages []ChatMessage `json:"messages"`
			}
			if json.Unmarshal(launderedBody, &rebuilt) == nil {
				req.Messages = rebuilt.Messages
			}
			if p.logger != nil {
				_ = p.logger.LogActionCtx(r.Context(), "guardrail-launder", r.URL.Path, fmt.Sprintf("stripped %d stale DefenseClaw block turn(s) from chat-completions request", stripped))
			}
		}
	}

	// --- Inject pending security notifications as a system message ---
	if p.notify != nil {
		if sysMsg := p.notify.FormatSystemMessage(); sysMsg != "" {
			fmt.Fprintf(os.Stderr, "[guardrail] injecting security notification into LLM request\n")
			notification := ChatMessage{Role: "system", Content: sysMsg}
			if len(req.RawBody) > 0 {
				if patched, err := injectSystemMessage(req.RawBody, sysMsg); err == nil {
					req.RawBody = patched
					req.Messages = append([]ChatMessage{notification}, req.Messages...)
				} else {
					fmt.Fprintf(os.Stderr, "[guardrail] inject system message into raw body failed: %v — falling back to structured messages\n", err)
					req.RawBody = nil
					req.Messages = append([]ChatMessage{notification}, req.Messages...)
				}
			} else {
				req.Messages = append([]ChatMessage{notification}, req.Messages...)
			}
			if p.logger != nil {
				_ = p.logger.LogActionCtx(r.Context(), "guardrail-notify-inject", "", "injected security notification into LLM request")
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
		agentName := p.agentNameForRequest(r.Header.Get("X-Agent-Name"))
		agentCtx, agentSpan = p.otel.StartAgentSpan(
			context.Background(),
			conversationID, agentName, "",
		)
	}
	if agentCtx == nil {
		agentCtx = context.Background()
	}

	// --- Pre-call inspection (apply_guardrail input, child of invoke_agent) ---
	userText := lastUserText(req.Messages)
	if userText != "" && !isHeartbeatMessage(userText, req.Messages) {
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
		p.recordTelemetry(r.Context(), "prompt", req.Model, verdict, elapsed, nil, nil)

		if verdict.Action == "block" && mode == "action" {
			if p.otel != nil && agentSpan != nil {
				p.otel.EndAgentSpan(agentSpan, "guardrail blocked")
			}
			msg := blockMessage(customBlockMsg, "prompt", verdict.Reason)
			p.enqueueBlockNotification(verdict, "prompt", req.Model)
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
			p.otel.EndLLMSpan(llmSpan, aliasModel, 0, 0, []string{"error"}, 0, "none", "", system, llmStartTime, "openclaw", p.agentIDForRequest())
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

		postCtx, postCancel := p.postCallContext(r.Context())
		respMessages := []ChatMessage{{Role: "assistant", Content: content}}
		verdict := p.inspector.Inspect(postCtx, "completion", content, respMessages, aliasModel, mode)
		elapsed := time.Since(t0)
		postCancel()

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
		p.recordTelemetry(r.Context(), "completion", aliasModel, verdict, elapsed, tokIn, tokOut)

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
				p.otel.EndLLMSpan(llmSpan, aliasModel, promptTok, completionTok, finishReasons, toolCallCount, guardrail, "blocked", system, llmStartTime, "openclaw", p.agentIDForRequest())
			}
			msg := blockMessage(customBlockMsg, "completion", verdict.Reason)
			p.enqueueBlockNotification(verdict, "completion", aliasModel)
			p.writeBlockedResponse(w, aliasModel, msg)
			return
		}
	}

	// --- Post-call inspection: tool call arguments ---
	if len(resp.Choices) > 0 && resp.Choices[0].Message != nil {
		if verdict := p.inspectToolCalls(resp.Choices[0].Message.ToolCalls); verdict != nil {
			p.recordTelemetry(r.Context(), "tool-call", aliasModel, verdict, 0, nil, nil)
			if verdict.Action == "block" && mode == "action" {
				if p.otel != nil && llmSpan != nil {
					promptTok, completionTok := 0, 0
					if resp.Usage != nil {
						promptTok = int(resp.Usage.PromptTokens)
						completionTok = int(resp.Usage.CompletionTokens)
					}
					p.otel.EndLLMSpan(llmSpan, aliasModel, promptTok, completionTok, finishReasons, toolCallCount, "local", "blocked", system, llmStartTime, "openclaw", p.agentIDForRequest())
				}
				msg := blockMessage(customBlockMsg, "completion",
					fmt.Sprintf("tool call blocked — %s", verdict.Reason))
				p.enqueueBlockNotification(verdict, "completion", aliasModel)
				p.writeBlockedResponse(w, aliasModel, msg)
				return
			}
		}
	}

	// --- Emit execute_tool spans for any tool_calls in the response ---
	if p.otel != nil && llmCtx != nil && len(resp.Choices) > 0 && resp.Choices[0].Message != nil {
		conversationID := r.Header.Get("X-Conversation-ID")
		agentName := p.agentNameForRequest(r.Header.Get("X-Agent-Name"))
		p.emitToolCallSpans(r.Context(), llmCtx, resp.Choices[0].Message.ToolCalls, aliasModel, mode, conversationID, agentName)
	}

	// End LLM span with response data.
	if p.otel != nil && llmSpan != nil {
		promptTok, completionTok := 0, 0
		if resp.Usage != nil {
			promptTok = int(resp.Usage.PromptTokens)
			completionTok = int(resp.Usage.CompletionTokens)
		}
		p.otel.EndLLMSpan(llmSpan, aliasModel, promptTok, completionTok, finishReasons, toolCallCount, guardrail, guardrailResult, system, llmStartTime, "openclaw", p.agentIDForRequest())
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
	const sseRoute = "/v1/chat/completions"
	var sseBytes int64
	if _, ok := w.(http.Flusher); !ok {
		writeOpenAIError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	mw := &sseByteMeter{ResponseWriter: w, n: &sseBytes}
	w = mw
	flusher, ok := interface{}(mw).(http.Flusher)
	if !ok {
		writeOpenAIError(mw, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	sseStart := time.Now()
	emitLifecycle(agentCtx, "stream", "stream.open", map[string]string{"route": sseRoute})
	if p.otel != nil {
		p.otel.RecordSSELifecycle(agentCtx, sseRoute, "open", "ok", 0, 0)
	}
	sseOutcome := "ok"
	defer func() {
		ms := time.Since(sseStart).Milliseconds()
		bytes := atomic.LoadInt64(&sseBytes)
		emitLifecycle(agentCtx, "stream", "stream.close", map[string]string{
			"route":       sseRoute,
			"duration_ms": fmt.Sprintf("%d", ms),
			"bytes_sent":  fmt.Sprintf("%d", bytes),
			"outcome":     sseOutcome,
		})
		if p.otel != nil {
			p.otel.RecordSSELifecycle(agentCtx, sseRoute, "close", sseOutcome, float64(ms), bytes)
		}
	}()

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

	const maxBufferedTCBytes = 10 << 20 // 10 MiB cap on buffered tool-call data

	var accumulated strings.Builder
	var tcAcc toolCallAccumulator
	var bufferedTCChunks [][]byte // tool-call chunks held until post-stream inspection
	bufferedTCSize := 0
	lastScanLen := 0
	streamFinishReasons := []string{}
	streamBlocked := false
	streamCtx, streamCancel := context.WithCancel(r.Context())
	defer streamCancel()

	// Initial text buffering: hold early chunks until enough text accumulates
	// for a meaningful guardrail scan, preventing partial output leakage.
	streamBufSize := 1024
	if p.cfg != nil && p.cfg.StreamBufferBytes > 0 {
		streamBufSize = p.cfg.StreamBufferBytes
	}
	var initialChunkBuf [][]byte
	initialBufFlushed := mode != "action"

	usage, err := upstream.ChatCompletionStream(streamCtx, req, func(chunk StreamChunk) {
		if streamBlocked {
			return
		}
		chunk.Model = aliasModel

		hasToolCalls := false
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta != nil {
			accumulated.WriteString(chunk.Choices[0].Delta.Content)
			if len(chunk.Choices[0].Delta.ToolCalls) > 0 {
				tcAcc.Merge(chunk.Choices[0].Delta.ToolCalls)
				hasToolCalls = true
			}
		}
		for _, c := range chunk.Choices {
			if c.FinishReason != nil && *c.FinishReason != "" {
				streamFinishReasons = append(streamFinishReasons, *c.FinishReason)
			}
		}

		const midStreamScanInterval = 500
		if accumulated.Len()-lastScanLen >= midStreamScanInterval && mode == "action" {
			midVerdict := p.inspector.InspectMidStream(r.Context(), "completion", accumulated.String(),
				[]ChatMessage{{Role: "assistant", Content: accumulated.String()}}, aliasModel, mode)
			if midVerdict.Severity != "NONE" && midVerdict.Action == "block" {
				fmt.Fprintf(os.Stderr, "[guardrail] STREAM-BLOCK severity=%s %s\n",
					midVerdict.Severity, redaction.Reason(midVerdict.Reason))
				p.recordTelemetry(r.Context(), "completion", aliasModel, midVerdict, 0, nil, nil)
				p.enqueueBlockNotification(midVerdict, "completion", aliasModel)
				streamBlocked = true
				streamCancel()
				return
			}
			lastScanLen = accumulated.Len()
		}

		data, _ := json.Marshal(chunk)

		isToolCallFinish := len(chunk.Choices) > 0 && chunk.Choices[0].FinishReason != nil &&
			*chunk.Choices[0].FinishReason == "tool_calls"
		if mode == "action" && (hasToolCalls || isToolCallFinish || len(bufferedTCChunks) > 0) {
			bufferedTCSize += len(data)
			if bufferedTCSize > maxBufferedTCBytes {
				fmt.Fprintf(os.Stderr, "[guardrail] STREAM-BLOCK buffered tool-call data exceeds %d bytes\n", maxBufferedTCBytes)
				streamBlocked = true
				streamCancel()
				return
			}
			bufferedTCChunks = append(bufferedTCChunks, data)
			return
		}

		if !initialBufFlushed {
			initialChunkBuf = append(initialChunkBuf, data)
			if accumulated.Len() >= streamBufSize {
				for _, buffered := range initialChunkBuf {
					fmt.Fprintf(w, "data: %s\n\n", buffered)
				}
				flusher.Flush()
				initialChunkBuf = nil
				initialBufFlushed = true
			}
			return
		}

		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	})
	// Flush any remaining initial buffer (short streams that completed
	// before reaching the buffer threshold). Run a guardrail check first.
	if !initialBufFlushed && !streamBlocked && len(initialChunkBuf) > 0 {
		if accumulated.Len() > 0 && mode == "action" {
			initVerdict := p.inspector.InspectMidStream(r.Context(), "completion", accumulated.String(),
				[]ChatMessage{{Role: "assistant", Content: accumulated.String()}}, aliasModel, mode)
			if initVerdict.Severity != "NONE" && initVerdict.Action == "block" {
				fmt.Fprintf(os.Stderr, "[guardrail] STREAM-PREBLOCK severity=%s %s\n",
					initVerdict.Severity, redaction.Reason(initVerdict.Reason))
				p.recordTelemetry(r.Context(), "completion", aliasModel, initVerdict, 0, nil, nil)
				p.enqueueBlockNotification(initVerdict, "completion", aliasModel)
				streamBlocked = true
			}
		}
		if !streamBlocked {
			for _, buffered := range initialChunkBuf {
				fmt.Fprintf(w, "data: %s\n\n", buffered)
			}
			flusher.Flush()
			initialBufFlushed = true
		}
	}
	if err != nil && !streamBlocked {
		sseOutcome = "error"
		emitGatewayError(agentCtx, gatewaylog.SubsystemStream, gatewaylog.ErrCodeUpstreamError,
			fmt.Sprintf("upstream stream error: %v", err), err)
		fmt.Fprintf(os.Stderr, "[guardrail] stream error: %v\n", err)
		if p.otel != nil && llmSpan != nil {
			p.otel.EndLLMSpan(llmSpan, aliasModel, 0, 0, []string{"error"}, 0, "none", "", system, llmStartTime, "openclaw", p.agentIDForRequest())
			llmSpan = nil
		}
	}

	guardrail := "none"
	guardrailResult := ""

	if streamBlocked {
		sseOutcome = "blocked"
		if p.otel != nil && llmSpan != nil {
			p.otel.EndLLMSpan(llmSpan, aliasModel, 0, 0, append(streamFinishReasons, "blocked"), 0, "local", "block", system, llmStartTime, "openclaw", p.agentIDForRequest())
		}
		msg := blockMessage(customBlockMsg, "completion", "content blocked mid-stream by guardrail")
		blockChunk := StreamChunk{
			ID: "chatcmpl-blocked", Object: "chat.completion.chunk",
			Created: time.Now().Unix(), Model: aliasModel,
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: "\n\n" + msg}}},
		}
		data, _ := json.Marshal(blockChunk)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
		return
	}

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

		postCtx, postCancel := p.postCallContext(r.Context())
		respMessages := []ChatMessage{{Role: "assistant", Content: content}}
		verdict := p.inspector.Inspect(postCtx, "completion", content, respMessages, aliasModel, mode)
		elapsed := time.Since(t0)
		postCancel()

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
		p.recordTelemetry(r.Context(), "completion", aliasModel, verdict, elapsed, tokIn, tokOut)

		if verdict.Severity != "NONE" {
			guardrail = "local"
			guardrailResult = verdict.Action
		}
	}

	// Final post-stream inspection: tool calls (fully reassembled).
	// Buffered tool-call chunks are released only if inspection passes.
	assembledTC := tcAcc.JSON()
	tcBlocked := false
	toolCallCount := countToolCalls(assembledTC)
	if len(assembledTC) > 0 {
		if verdict := p.inspectToolCalls(assembledTC); verdict != nil {
			p.recordTelemetry(r.Context(), "tool-call", aliasModel, verdict, 0, nil, nil)
			if verdict.Action == "block" && mode == "action" {
				tcBlocked = true
				guardrail = "local"
				guardrailResult = "block"
				msg := blockMessage(customBlockMsg, "completion",
					fmt.Sprintf("tool call blocked — %s", verdict.Reason))
				blockChunk := StreamChunk{
					ID: "chatcmpl-blocked", Object: "chat.completion.chunk",
					Created: time.Now().Unix(), Model: aliasModel,
					Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: "\n\n" + msg}}},
				}
				data, _ := json.Marshal(blockChunk)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}
	}

	if p.otel != nil && llmSpan != nil {
		promptTok, completionTok := 0, 0
		if usage != nil {
			promptTok = int(usage.PromptTokens)
			completionTok = int(usage.CompletionTokens)
		}
		p.otel.EndLLMSpan(llmSpan, aliasModel, promptTok, completionTok, streamFinishReasons, toolCallCount, guardrail, guardrailResult, system, llmStartTime, "openclaw", p.agentIDForRequest())
	}

	// Flush buffered tool-call chunks only when inspection passed.
	if !tcBlocked {
		for _, buf := range bufferedTCChunks {
			fmt.Fprintf(w, "data: %s\n\n", buf)
		}
		if len(bufferedTCChunks) > 0 {
			flusher.Flush()
		}
	}

	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// ---------------------------------------------------------------------------
// Blocked response helpers
// ---------------------------------------------------------------------------

// enqueueBlockNotification pushes a SecurityNotification describing a
// guardrail block onto the shared NotificationQueue so that subsequent
// requests — from any session, via any provider surface — carry the
// enforcement context as a `system` message via FormatSystemMessage.
//
// Rationale: the synchronous block response we return to the client
// shows the `[DefenseClaw]` banner inline in the user's UI, but the
// *LLM* doesn't see that banner on the next turn except as whatever
// fragment the client chooses to replay in conversation history. By
// enqueueing a notification on every block site, the next proxy call
// prepends an authoritative `[DEFENSECLAW SECURITY ENFORCEMENT] …`
// block to the request so the model acknowledges the enforcement
// instead of silently retrying the refused request.
//
// Companion to blockMessage() — both should be called at every block
// site. No-op when notify is nil or verdict is nil so callers don't
// need a guard at each site.
func (p *GuardrailProxy) enqueueBlockNotification(verdict *ScanVerdict, direction, model string) {
	if p.notify == nil || verdict == nil {
		return
	}
	// SubjectType drives the "Skill"/"Plugin"/"MCP"/"Tool" label in
	// FormatSystemMessage. "prompt" / "completion" aren't one of the
	// recognized keys, so they fall through to the "Skill" label
	// which renders fine — but we also pass them so downstream sinks
	// can distinguish input-side vs. output-side blocks.
	subject := direction
	if subject != "prompt" && subject != "completion" {
		subject = "prompt"
	}
	findings := 0
	if verdict.Findings != nil {
		findings = len(verdict.Findings)
	}
	p.notify.Push(SecurityNotification{
		SubjectType: subject,
		// SkillName is rendered verbatim in the enforcement notice.
		// Use the model name so operators and the LLM both see which
		// target the block applied to; not sensitive and always
		// present at block time.
		SkillName: model,
		Severity:  verdict.Severity,
		Findings:  findings,
		Actions:   []string{"block"},
		// verdict.Reason is minted from user content in the regex
		// path and can carry literal secrets/PII. Always scrub
		// before the text lands in a system message that gets
		// shipped off-box to the LLM provider.
		Reason: redaction.ForSinkReason(verdict.Reason),
	})
}

func (p *GuardrailProxy) writeBlockedResponse(w http.ResponseWriter, model, msg string) {
	finishReason := "content_filter"
	blocked := true
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
		Usage:              &ChatUsage{},
		DefenseClawBlocked: &blocked,
		DefenseClawReason:  msg,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-DefenseClaw-Blocked", "true")
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
	w.Header().Set("X-DefenseClaw-Blocked", "true")
	w.WriteHeader(http.StatusOK)

	created := time.Now().Unix()
	id := "chatcmpl-blocked"
	blocked := true

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

	// Final chunk with finish_reason and block metadata.
	fr := "content_filter"
	chunk2 := StreamChunk{
		ID: id, Object: "chat.completion.chunk", Created: created, Model: model,
		Choices:            []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &fr}},
		DefenseClawBlocked: &blocked,
		DefenseClawReason:  msg,
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
			"finishReason": "SAFETY",
			"index":        0,
		}},
		"defenseclaw_blocked": true,
		"defenseclaw_reason":  msg,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-DefenseClaw-Blocked", "true")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// writeBlockedResponseOpenAIResponses returns a blocked response in OpenAI
// Responses API format (non-streaming).
//
// Design note: we deliberately emit `status: "completed"` (not "incomplete"
// with `incomplete_details.reason = "content_filter"`) because changing it
// risks openai-codex CLI, ChatGPT, and other Responses API clients silently
// discarding the `output[]` array — which would hide the `[DefenseClaw]`
// banner the user needs to see. DefenseClaw-aware clients should instead
// detect blocks via the `X-DefenseClaw-Blocked` header and the
// `defenseclaw_blocked` / `defenseclaw_reason` payload fields.
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
		"defenseclaw_blocked": true,
		"defenseclaw_reason":  msg,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-DefenseClaw-Blocked", "true")
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
	w.Header().Set("X-DefenseClaw-Blocked", "true")
	w.WriteHeader(http.StatusOK)

	writeSSE := func(eventType string, data interface{}) {
		raw, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, raw)
		flusher.Flush()
	}

	respID := "resp_blocked"
	// IMPORTANT: the OpenAI Responses API (and the ChatGPT /backend-api
	// Codex backend that ride on it) strictly validate item IDs in the
	// conversation input array — assistant `message` items must have
	// IDs starting with `msg`. Before this fix the stream emitted
	// `item_blocked`, which the client happily persisted into its
	// local history; on the *next* turn the Responses API rejected the
	// whole conversation with `Invalid 'input[N].id': 'item_blocked'.
	// Expected an ID that begins with 'msg'.`, wedging the TUI after
	// any DefenseClaw block.
	//
	// Non-streaming siblings (writeBlockedResponseOpenAIResponses,
	// writeBlockedResponseAnthropic) already use a `msg_*` prefix —
	// keep the streaming path consistent with both the spec and the
	// rest of the block surface.
	itemID := "msg_blocked"

	writeSSE("response.created", map[string]interface{}{
		"type": "response.created",
		"response": map[string]interface{}{
			"id": respID, "object": "response", "model": model,
			"status": "in_progress", "output": []interface{}{},
		},
	})
	writeSSE("response.output_item.added", map[string]interface{}{
		"type":         "response.output_item.added",
		"response_id":  respID,
		"output_index": 0,
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
//
// Design note: we deliberately emit `stop_reason: "end_turn"` rather than
// `"refusal"` for the same reason as writeBlockedResponseOpenAIResponses —
// some Anthropic SDKs / agent stacks treat `refusal` as "no content" and
// suppress the message body, which would hide the `[DefenseClaw]` banner.
// DefenseClaw-aware clients should detect blocks via the
// `X-DefenseClaw-Blocked` header and `defenseclaw_blocked` payload field.
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
		"usage":               map[string]int{"input_tokens": 0, "output_tokens": 1},
		"defenseclaw_blocked": true,
		"defenseclaw_reason":  msg,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-DefenseClaw-Blocked", "true")
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
	w.Header().Set("X-DefenseClaw-Blocked", "true")
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

func (p *GuardrailProxy) authenticateRequest(w http.ResponseWriter, r *http.Request) bool {
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

	reason := "invalid_token"
	if strings.TrimSpace(r.Header.Get("X-DC-Auth")) == "" && (p.masterKey == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")) {
		reason = "missing_token"
	}
	p.emitProxyAuthFailure(r, reason)
	return false
}

func (p *GuardrailProxy) emitProxyAuthFailure(r *http.Request, metricReason string) {
	ctx := r.Context()
	route := r.URL.Path
	if r.Pattern != "" {
		route = r.Pattern
	}
	code := gatewaylog.ErrCodeAuthInvalidToken
	if metricReason == "missing_token" {
		code = gatewaylog.ErrCodeAuthMissingToken
	}
	msg := fmt.Sprintf("guardrail proxy auth failure (client_ip=%s ua=%q)",
		ClientIPRedacted(r), TruncateUserAgent256(r.UserAgent()))
	emitGatewayError(ctx, gatewaylog.SubsystemAuth, code, msg, nil)
	if p.otel != nil {
		p.otel.RecordHTTPAuthFailure(ctx, route, metricReason)
	}
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
		// Message bodies are verbatim user/assistant text. The
		// original length is preserved in the log so operators
		// can still see whether a payload was trimmed by the
		// caller; only the preview itself is masked when
		// Reveal is off.
		preview := truncateLog(redaction.MessageContent(msg.Content), 500)
		fmt.Fprintf(os.Stderr, "  \033[2m[%d]\033[0m %s (%d chars): %s\n", i, msg.Role, len(msg.Content), preview)
	}

	logVerdict(severity, action, verdict, elapsed)
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
	// LLM responses can echo user PII (the model re-emits
	// personal data verbatim in summaries, translations, etc.)
	// or surface new secrets authored by the model itself. Both
	// flows are operator-facing; the Reveal flag gates
	// unredacted output for live debugging.
	preview := truncateLog(redaction.MessageContent(content), 800)
	fmt.Fprintf(os.Stderr, "  response (%d chars): %s\n", len(content), preview)

	logVerdict(severity, action, verdict, elapsed)
	fmt.Fprintf(os.Stderr, "\033[92m%s\033[0m\n", strings.Repeat("─", 60))
}

func logVerdict(severity, action string, verdict *ScanVerdict, elapsed time.Duration) {
	scannerStr := ""
	if verdict.Scanner != "" {
		scannerStr = "  scanner=" + verdict.Scanner
	}
	if severity == "NONE" {
		fmt.Fprintf(os.Stderr, "  verdict: \033[92m%s\033[0m%s\n", severity, scannerStr)
	} else {
		// verdict.Reason and verdict.Findings originate from
		// scanners that may include the matched literal
		// ("detected SSN 123-45-6789", "ghp_abc..."). Run both
		// through redaction.Reason so rule-IDs pass verbatim
		// but raw literals are masked unless Reveal is set.
		fmt.Fprintf(os.Stderr, "  verdict: \033[91m%s\033[0m  action=%s%s  %s\n",
			severity, action, scannerStr, redaction.Reason(verdict.Reason))
		if len(verdict.Findings) > 0 {
			scrubbed := make([]string, len(verdict.Findings))
			for i, f := range verdict.Findings {
				scrubbed[i] = redaction.Reason(f)
			}
			fmt.Fprintf(os.Stderr, "  findings: %s\n", strings.Join(scrubbed, ", "))
		}
		if len(verdict.ScannerSources) > 0 {
			// ScannerSources is a fixed enum
			// (local-pattern, cisco-ai-defense, judge-gpt4,
			// etc.) — authored metadata only, never PII.
			fmt.Fprintf(os.Stderr, "  sources: %s\n", strings.Join(verdict.ScannerSources, ", "))
		}
	}
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

// isOllamaLoopback returns true when targetURL points at a loopback
// address (localhost, 127.0.0.1, ::1) on one of the Ollama ports
// listed in providers.json.  The guardrailPort is excluded so the
// proxy never forwards to itself.
func isOllamaLoopback(targetURL string, guardrailPort int) bool {
	u, err := url.Parse(targetURL)
	if err != nil || len(ollamaPorts) == 0 {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return false
	}
	portStr := u.Port()
	if portStr == "" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	if port == guardrailPort {
		return false
	}
	for _, op := range ollamaPorts {
		if port == op {
			return true
		}
	}
	return false
}

// isKnownProviderDomain returns true when the hostname of targetURL
// matches a domain from the embedded providers.json list or is an
// Ollama loopback address.  Only the parsed hostname is checked —
// query strings and path components are ignored to prevent bypass via
// crafted URLs like https://evil.com/?foo=api.openai.com.
func isKnownProviderDomain(targetURL string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, pd := range providerDomains {
		if matchProviderDomain(host, u.Path, pd.domain) {
			return true
		}
	}
	return isOllamaLoopback(targetURL, 0)
}

// matchProviderDomain performs safe domain matching:
//   - Domains ending in "." are hostname prefixes (e.g. "bedrock-runtime.")
//   - Domains containing "/" match hostname+path prefix
//   - All others require exact hostname or subdomain match
func matchProviderDomain(host, urlPath, domain string) bool {
	d := strings.ToLower(domain)
	if strings.HasSuffix(d, ".") {
		return strings.HasPrefix(host, d)
	}
	if strings.Contains(d, "/") {
		parts := strings.SplitN(d, "/", 2)
		domainPart, pathPart := parts[0], "/"+parts[1]
		if host != domainPart && !strings.HasSuffix(host, "."+domainPart) {
			return false
		}
		return strings.HasPrefix(urlPath, pathPart)
	}
	return host == d || strings.HasSuffix(host, "."+d)
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

func (p *GuardrailProxy) recordTelemetry(ctx context.Context, direction, model string, verdict *ScanVerdict, elapsed time.Duration, tokIn, tokOut *int64) {
	requestID := RequestIDFromContext(ctx)
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

	// Emit canonical finding IDs for cross-scanner correlation. The scanner
	// (local-pattern / CiscoAID / judge) produces raw finding strings; the
	// normalizer maps them to a stable ID scheme so downstream tooling can
	// match findings across scanners without parsing scanner-specific formats.
	if nfs := NormalizeScanVerdict(verdict); len(nfs) > 0 {
		ids := make([]string, 0, len(nfs))
		seen := make(map[string]bool, len(nfs))
		for _, nf := range nfs {
			if seen[nf.CanonicalID] {
				continue
			}
			seen[nf.CanonicalID] = true
			ids = append(ids, nf.CanonicalID)
			if len(ids) >= 8 {
				break
			}
		}
		details += fmt.Sprintf(" canonical=%s", strings.Join(ids, ","))
	}
	if requestID != "" {
		// Append the correlation key so the human-readable gateway.log
		// line (which skips structured sinks) is still searchable by
		// operators who grep for a specific request ID.
		details += fmt.Sprintf(" request_id=%s", requestID)
	}

	if p.logger != nil {
		// v7: route the verdict audit row through the context-aware
		// path so every envelope dimension the CorrelationMiddleware
		// stamped (trace_id, session_id, agent_*, policy_id,
		// destination_app, tool_*) is persisted next to the
		// human-readable details string. LogActionWithCorrelation
		// only carries trace_id + request_id — the other dimensions
		// used to be silently dropped on the SQLite row even when
		// the matching gateway.jsonl row had them. See review
		// finding C1 for the coverage-gap writeup.
		_ = p.logger.LogActionCtx(ctx, "guardrail-verdict", model, details)
	}
	if p.store != nil {
		// guardrail-inspection is the SQLite-only twin row the
		// proxy writes for the TUI's alerts panel. Keep the same
		// envelope as the logger row above — otherwise dashboards
		// pivoting on agent_id would see two conflicting rows for
		// the same verdict.
		evt := audit.Event{
			Action:    "guardrail-inspection",
			Target:    model,
			Severity:  verdict.Severity,
			Details:   details,
			Timestamp: time.Now().UTC(),
			RequestID: requestID,
		}
		audit.ApplyEnvelope(&evt, audit.EnvelopeFromContext(ctx))
		_ = p.store.LogEvent(evt)
	}

	if p.logger != nil {
		_ = p.logger.LogActionWithCorrelation("guardrail-verdict", model, details, "", requestID)
	}
	_ = persistAuditEvent(p.logger, p.store, audit.Event{
		Action:    "guardrail-inspection",
		Target:    model,
		Severity:  verdict.Severity,
		Details:   details,
		Timestamp: time.Now().UTC(),
		RequestID: requestID,
	})

	if p.otel != nil {
		// v7: use the request's own ctx (carries the active trace
		// span) so histograms get trace-exemplar links in Splunk.
		// The previous context.Background() shadow broke the
		// metrics→traces join for every guardrail observation —
		// operators following a span from traces could not see
		// the accompanying latency / token histogram data points.
		p.otel.RecordGuardrailEvaluation(ctx, "guardrail-proxy", verdict.Action)
		p.otel.RecordGuardrailLatency(ctx, "guardrail-proxy", elapsedMs)
		if verdict.CiscoElapsedMs > 0 {
			p.otel.RecordGuardrailLatency(ctx, "cisco-ai-defense", verdict.CiscoElapsedMs)
			p.otel.RecordGuardrailEvaluation(ctx, "cisco-ai-defense", verdict.Action)
		}
		if tokIn != nil || tokOut != nil {
			p.otel.RecordLLMTokens(ctx, "apply_guardrail", "defenseclaw", model, "openclaw", p.agentIDForRequest(), ptrOr(tokIn, 0), ptrOr(tokOut, 0))
		}
	}

	if p.webhooks != nil && verdict.Action == "block" {
		event := audit.Event{
			ID:        uuid.New().String(),
			Timestamp: time.Now().UTC(),
			Action:    "guardrail-block",
			Target:    model,
			Actor:     "defenseclaw-guardrail",
			Details:   details,
			Severity:  verdict.Severity,
		}
		// v7: webhook payloads are one of the five external-facing
		// surfaces; Splunk/PagerDuty/Slack consumers pivot on the same
		// envelope dimensions as gateway.jsonl. Stamping here keeps the
		// webhook body in lockstep with the matching logger/store rows.
		audit.ApplyEnvelope(&event, audit.EnvelopeFromContext(ctx))
		p.webhooks.Dispatch(event)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// injectSystemMessage prepends a system message to the "messages" array in
// the raw JSON body. This preserves all other fields the client sent.
// Works for OpenAI Chat Completions, Anthropic (also uses "messages"), and
// any other API that mirrors the Chat Completions schema.
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

// injectSystemMessageForResponsesAPI merges the notification content into the
// top-level `instructions` string of an OpenAI Responses API request. This
// is the canonical system-prompt slot for the Responses API (used by e.g.
// ChatGPT's /backend-api/codex/responses endpoint, which openai-codex/gpt-5.x
// targets).
//
// Why not prepend into `input[]` instead? The Responses API input items have
// strict schema — assistant `message` items must have IDs starting with
// `msg_`, system items have a different shape again, and the API rejects
// unknown IDs in the conversation history. Mutating `input[]` is fragile;
// `instructions` is documented as the system prompt and accepts arbitrary
// text. See also handlePassthrough where we return `msg_blocked` as the
// item ID for the same reason.
//
// The notification content is prepended (not appended) so it wins if the
// caller's instructions otherwise contradict the enforcement notice.
func injectSystemMessageForResponsesAPI(raw json.RawMessage, content string) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("proxy: inject responses instructions: unmarshal: %w", err)
	}

	existing := ""
	if cur, ok := m["instructions"]; ok {
		// Tolerate the field being a JSON string or missing.
		if err := json.Unmarshal(cur, &existing); err != nil {
			// If it's not a string we can't safely mutate it — skip.
			return nil, fmt.Errorf("proxy: inject responses instructions: non-string instructions: %w", err)
		}
	}
	merged := content
	if existing != "" {
		merged = content + "\n\n" + existing
	}
	mergedBytes, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("proxy: inject responses instructions: marshal: %w", err)
	}
	m["instructions"] = mergedBytes
	return json.Marshal(m)
}

// defenseClawBlockBanner is the content prefix every synthetic
// block message we emit starts with (see blockMessage in guardrail.go).
// Used as the detection signal for laundering — any assistant turn in
// an incoming request whose text starts with this prefix was generated
// by DefenseClaw on a prior turn, persisted in the client's local
// conversation history, and is being replayed back at us. We strip
// those from the upstream body so the LLM isn't seeing stale fake
// refusals alongside the current notification-queue system message.
const defenseClawBlockBanner = "[DefenseClaw]"

// defenseClawBlockIDPrefix is the item-ID prefix we emit for synthetic
// assistant messages on OpenAI Responses API and Anthropic block paths.
// Detected (in addition to the content prefix) so laundering still
// catches a block message even if the client rewrote the content.
const defenseClawBlockIDPrefix = "msg_blocked"

// responsesTextFromContent walks the Responses API `content` array
// (which is `[{type: "output_text" | "input_text", text: "..."}]`) and
// concatenates the text fields. Returns "" when content isn't an array
// or contains no text parts.
func responsesTextFromContent(content json.RawMessage) string {
	if len(content) == 0 || content[0] != '[' {
		return ""
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(content, &parts); err != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p.Text)
	}
	return b.String()
}

// launderChatCompletionsHistory removes assistant turns from the
// `messages` array whose content begins with the DefenseClaw banner
// prefix. Handles the Chat Completions / Anthropic Messages shape where
// `content` is a plain string; assistant turns with structured content
// (array of parts) are probed via their first `text` part. Returns the
// mutated body, the count of stripped turns, and any parse error.
//
// No-op when the body has no `messages` field or no qualifying assistant
// turns — in that case returns the original raw bytes.
func launderChatCompletionsHistory(raw json.RawMessage) (json.RawMessage, int, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw, 0, fmt.Errorf("proxy: launder chat history: unmarshal: %w", err)
	}
	msgBytes, ok := m["messages"]
	if !ok {
		return raw, 0, nil
	}
	var messages []json.RawMessage
	if err := json.Unmarshal(msgBytes, &messages); err != nil {
		return raw, 0, fmt.Errorf("proxy: launder chat history: unmarshal messages: %w", err)
	}
	stripped := 0
	kept := make([]json.RawMessage, 0, len(messages))
	for _, item := range messages {
		var probe struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(item, &probe) == nil && probe.Role == "assistant" && len(probe.Content) > 0 {
			var text string
			switch probe.Content[0] {
			case '"':
				_ = json.Unmarshal(probe.Content, &text)
			case '[':
				text = responsesTextFromContent(probe.Content)
			}
			if strings.HasPrefix(text, defenseClawBlockBanner) {
				stripped++
				continue
			}
		}
		kept = append(kept, item)
	}
	if stripped == 0 {
		return raw, 0, nil
	}
	newMsgBytes, err := json.Marshal(kept)
	if err != nil {
		return raw, 0, fmt.Errorf("proxy: launder chat history: marshal messages: %w", err)
	}
	m["messages"] = newMsgBytes
	out, err := json.Marshal(m)
	if err != nil {
		return raw, 0, fmt.Errorf("proxy: launder chat history: marshal body: %w", err)
	}
	return out, stripped, nil
}

// launderResponsesHistory removes assistant items from the Responses
// API `input` array whose id starts with `msg_blocked` OR whose
// aggregated text begins with the DefenseClaw banner. Both signals are
// checked because a cautious client may rewrite the ID (rare) and a
// misbehaving client may rewrite the text (also rare) — catching either
// makes laundering robust against both kinds of drift.
//
// When `input` is a plain string (not an array) or absent, the body
// is returned unchanged.
func launderResponsesHistory(raw json.RawMessage) (json.RawMessage, int, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw, 0, fmt.Errorf("proxy: launder responses history: unmarshal: %w", err)
	}
	inputBytes, ok := m["input"]
	if !ok || len(inputBytes) == 0 || inputBytes[0] != '[' {
		return raw, 0, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(inputBytes, &items); err != nil {
		return raw, 0, fmt.Errorf("proxy: launder responses history: unmarshal input: %w", err)
	}
	stripped := 0
	kept := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		var probe struct {
			Type    string          `json:"type"`
			Role    string          `json:"role"`
			ID      string          `json:"id"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(item, &probe) == nil && probe.Role == "assistant" {
			if strings.HasPrefix(probe.ID, defenseClawBlockIDPrefix) {
				stripped++
				continue
			}
			if strings.HasPrefix(responsesTextFromContent(probe.Content), defenseClawBlockBanner) {
				stripped++
				continue
			}
		}
		kept = append(kept, item)
	}
	if stripped == 0 {
		return raw, 0, nil
	}
	newInputBytes, err := json.Marshal(kept)
	if err != nil {
		return raw, 0, fmt.Errorf("proxy: launder responses history: marshal input: %w", err)
	}
	m["input"] = newInputBytes
	out, err := json.Marshal(m)
	if err != nil {
		return raw, 0, fmt.Errorf("proxy: launder responses history: marshal body: %w", err)
	}
	return out, stripped, nil
}

// launderInboundHistory dispatches to the correct format-specific
// launderer based on the request path. Returns the (possibly mutated)
// body and the count of stripped turns. Errors are logged at the call
// site but never fail the request — a laundering failure should never
// block a legitimate user.
func launderInboundHistory(raw json.RawMessage, path string) (json.RawMessage, int) {
	if strings.HasSuffix(path, "/responses") {
		out, n, err := launderResponsesHistory(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] launder responses history: %v\n", err)
			return raw, 0
		}
		return out, n
	}
	if strings.HasSuffix(path, "/chat/completions") || strings.Contains(path, "/messages") {
		out, n, err := launderChatCompletionsHistory(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] launder chat history: %v\n", err)
			return raw, 0
		}
		return out, n
	}
	return raw, 0
}

// injectNotificationForPassthrough dispatches to the correct format-aware
// injector based on the provider/path the request is bound for. Returns
// the mutated raw body and a label describing the injection site for
// observability. When no known injection path applies, returns the
// original bytes and the empty label with a non-nil error.
//
// Current coverage:
//   - OpenAI Chat Completions (path ends in /chat/completions, or provider=openai
//     with `messages` field) → inject into `messages[]`
//   - OpenAI Responses API (path ends in /responses) → inject into `instructions`
//
// Deferred (follow-up): Anthropic top-level `system`, Gemini
// `systemInstruction`. Those providers currently bypass notification
// injection entirely in the passthrough path — they still get notifications
// pushed onto the queue by enqueueBlockNotification, but the queue content
// only reaches the LLM when the *next* request happens to go through
// handleChatCompletion or hits one of the wired paths above. That gap is
// acceptable for this PR because (a) notifications are TTL-bounded so
// stale-ness is self-correcting, (b) most OSS agent stacks route through
// OpenAI-compatible endpoints, and (c) adding Anthropic/Gemini injection
// requires per-provider payload synthesis that would double PR scope.
func injectNotificationForPassthrough(raw json.RawMessage, content, path string) (json.RawMessage, string, error) {
	if strings.HasSuffix(path, "/responses") {
		out, err := injectSystemMessageForResponsesAPI(raw, content)
		if err != nil {
			return raw, "", err
		}
		return out, "responses-api/instructions", nil
	}
	if strings.HasSuffix(path, "/chat/completions") || strings.Contains(path, "/messages") {
		out, err := injectSystemMessage(raw, content)
		if err != nil {
			return raw, "", err
		}
		return out, "chat-completions/messages", nil
	}
	return raw, "", fmt.Errorf("proxy: inject passthrough: no known injection path for %q", path)
}

// ---------------------------------------------------------------------------
// Tool call inspection (defense-in-depth)
//
// When the LLM responds with tool_calls, inspect each tool's name and
// arguments with the same ScanAllRules engine used by the inspect endpoint.
// This catches dangerous tool calls (write_file with /etc/passwd, shell with
// reverse shells, etc.) even when the OpenClaw plugin is not loaded.
//
// In "action" mode, tool-call chunks are buffered and only released after
// post-stream inspection passes. In "observe" mode, tool-call deltas are
// forwarded to the client as they arrive (by design) and the post-stream
// scan is purely alerting.
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
		fmt.Fprintf(os.Stderr, "[guardrail] TOOL-CALL-INSPECT parse error (blocking): %v\n", err)
		if p.logger != nil {
			_ = p.logger.LogAction("guardrail-tool-call-parse-error", "", err.Error())
		}
		return &ScanVerdict{
			Action:         "block",
			Severity:       "HIGH",
			Reason:         "tool_calls JSON parse error — cannot inspect, failing closed",
			ScannerSources: []string{"tool-call-inspect"},
		}
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

// toolCallAccumulator merges streaming tool-call deltas by index, properly
// concatenating function.arguments fragments so the final output contains
// fully-assembled tool calls suitable for inspection.
type toolCallAccumulator struct {
	calls []accToolCall
}

type accToolCall struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// Merge incorporates a raw tool_calls delta array from a single SSE chunk.
func (a *toolCallAccumulator) Merge(delta json.RawMessage) {
	if len(delta) == 0 {
		return
	}
	var deltas []accToolCall
	if json.Unmarshal(delta, &deltas) != nil {
		return
	}
	for _, d := range deltas {
		idx := d.Index
		for idx >= len(a.calls) {
			a.calls = append(a.calls, accToolCall{Index: len(a.calls)})
		}
		if d.ID != "" {
			a.calls[idx].ID = d.ID
		}
		if d.Type != "" {
			a.calls[idx].Type = d.Type
		}
		if d.Function.Name != "" {
			a.calls[idx].Function.Name = d.Function.Name
		}
		a.calls[idx].Function.Arguments += d.Function.Arguments
	}
}

// JSON returns the fully assembled tool calls as a JSON array suitable
// for inspectToolCalls. Returns nil when no calls have been accumulated.
func (a *toolCallAccumulator) JSON() json.RawMessage {
	if len(a.calls) == 0 {
		return nil
	}
	out, err := json.Marshal(a.calls)
	if err != nil {
		return nil
	}
	return out
}

// mergeToolCallChunks is a backwards-compatible wrapper used only by tests
// and non-streaming callers. For streaming, use toolCallAccumulator.
func mergeToolCallChunks(existing json.RawMessage, chunk json.RawMessage) json.RawMessage {
	if len(chunk) == 0 {
		return existing
	}
	if len(existing) == 0 {
		return chunk
	}

	var existingArr []json.RawMessage
	var chunkArr []json.RawMessage
	if json.Unmarshal(existing, &existingArr) != nil {
		return chunk
	}
	if json.Unmarshal(chunk, &chunkArr) != nil {
		return existing
	}
	merged := append(existingArr, chunkArr...)
	out, err := json.Marshal(merged)
	if err != nil {
		return existing
	}
	return out
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
//
// conversationID and agentName are threaded from the originating request so
// downstream SIEMs can correlate tool_call rows with the parent agent run.
func (p *GuardrailProxy) emitToolCallSpans(reqCtx, llmCtx context.Context, raw json.RawMessage, model, mode, conversationID, agentName string) {
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
			telemetry.ToolSpanContext{
				ToolID:         tc.ID,
				SessionID:      conversationID,
				DestinationApp: "builtin",
				PolicyID:       p.defaultPolicyID,
				AgentName:      agentName,
			},
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

// sseByteMeter counts bytes written to an SSE response for observability.
type sseByteMeter struct {
	http.ResponseWriter
	n *int64
}

func (s *sseByteMeter) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	if s.n != nil {
		atomic.AddInt64(s.n, int64(n))
	}
	return n, err
}

func (s *sseByteMeter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
