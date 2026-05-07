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
	"crypto/sha256"
	"crypto/subtle"
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
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/time/rate"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/google/uuid"
)

// guardrailListenAddr returns the TCP listen address for the guardrail HTTP server.
// Loopback-style hosts bind 127.0.0.1 only. Any other host (e.g. a veth / bridge
// IP for openshell standalone sandbox) binds that address so peers outside the
// host loopback namespace can connect.
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
	// SetHILTConfig pushes the live human-in-the-loop view from
	// config.yaml into the inspector so the Rego policy reads
	// ``input.hilt.*`` from the latest values. Implementations that
	// don't care about HILT (e.g., test doubles) can no-op.
	SetHILTConfig(enabled bool, minSeverity string)
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

	// connector is the active agent framework adapter. It handles
	// authentication and request signal extraction. When nil, the
	// proxy falls back to its built-in auth and routing logic for
	// backward compatibility.
	connector connector.Connector

	inspector    ContentInspector
	masterKey    string
	gatewayToken string // gateway token, accepted in X-DC-Auth
	notify       *NotificationQueue
	webhooks     *WebhookDispatcher
	hilt         *HILTApprovalManager

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

	// registry + setupOpts enable runtime connector hot-swap when the
	// "connector" key appears in guardrail_runtime.json.
	registry  *connector.Registry
	setupOpts connector.SetupOpts

	// Observability defaults set at bootstrap. defaultAgentName
	// falls back to cfg.Claw.Mode ("openclaw") when the request
	// does not carry an agent identifier; defaultPolicyID is the
	// active guardrail / admission policy identifier threaded into
	// tool and approval spans so per-policy aggregations in the
	// Splunk Local Bridge / AgentWatch summary work correctly.
	defaultAgentName string
	defaultPolicyID  string

	// skipAuthForTest is a test-only escape hatch: when true,
	// authenticateRequest returns true without consulting the
	// connector / token / master-key. Plan B2 fails authentication
	// closed when no token is configured; the bulk of proxy_test.go
	// constructs a proxy directly without going through
	// NewGuardrailProxy (no token plumbing) and asserts behavior
	// downstream of auth. Tests that DO exercise the auth path
	// (TestTokenAuth_*, etc.) leave this false and present a real
	// X-DC-Auth header. Production callers MUST never set this —
	// it bypasses the security floor entirely.
	skipAuthForTest bool
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

// SetHILTApprovalManager wires the human approval bridge used for guardrail
// confirm verdicts.
func (p *GuardrailProxy) SetHILTApprovalManager(m *HILTApprovalManager) {
	p.hilt = m
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

// connectorName returns the active connector's name for telemetry labels.
func (p *GuardrailProxy) connectorName() string {
	if p.connector != nil {
		return p.connector.Name()
	}
	return "unknown"
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

func (p *GuardrailProxy) resolveConfirm(ctx context.Context, r *http.Request, verdict *ScanVerdict, direction, model, mode string) {
	// Prompt-surface UX contract: confirm verdicts on the prompt
	// direction have no native approval surface on any current
	// connector. The chat-message HITL fallback that used to fire
	// here is unusable (operators couldn't reply in the right
	// format; the message itself re-triggered scanners), so we
	// demote prompt confirms to alert before any HILT call. We
	// deliberately scope this guard to confirm — block verdicts on
	// the prompt direction are already demoted upstream in the
	// inspector chokepoint, and tests that construct synthetic
	// block verdicts directly should not be intercepted here.
	if verdict != nil && isPromptDirection(direction) && verdict.Action == guardrailActionConfirm {
		original := verdict.Action
		verdict.Action = guardrailActionAlert
		verdict.Reason = appendVerdictReason(verdict.Reason,
			fmt.Sprintf("policy-action=%s %s", original, promptSurfaceClampReason))
		return
	}

	if verdict == nil || mode != "action" || verdict.Action != guardrailActionConfirm {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	subject := guardrailApprovalSubject(direction, model)
	if p == nil || p.hilt == nil {
		verdict.Action = guardrailActionAlert
		verdict.Reason = appendVerdictReason(verdict.Reason, "human approval unsupported on this connector surface")
		if p != nil && p.logger != nil {
			_ = p.logger.LogActionCtx(ctx, hiltStatusUnsupported, subject, "surface=guardrail-proxy")
		}
		return
	}

	approved, status, err := p.hilt.Request(ctx, hiltSessionID(ctx, r), subject, verdict.Severity, verdict.Reason, 0)
	if approved {
		verdict.Action = guardrailActionAllow
		verdict.Reason = appendVerdictReason(verdict.Reason, "human approved once")
		return
	}
	if status == hiltStatusUnsupported {
		verdict.Action = guardrailActionAlert
		verdict.Reason = appendVerdictReason(verdict.Reason, "human approval unsupported on this connector surface")
		return
	}

	verdict.Action = guardrailActionBlock
	verdict.Reason = appendVerdictReason(verdict.Reason, hiltBlockReason(status, err))
}

func guardrailApprovalSubject(direction, model string) string {
	surface := "guardrail action"
	switch strings.TrimSpace(direction) {
	case "prompt":
		surface = "LLM prompt"
	case "completion":
		surface = "LLM completion"
	case "tool-call", "tool_call":
		surface = "LLM tool call"
	}
	if strings.TrimSpace(model) == "" {
		return surface
	}
	return surface + " for " + strings.TrimSpace(model)
}

func hiltSessionID(ctx context.Context, r *http.Request) string {
	if r != nil {
		env := audit.EnvelopeFromContext(r.Context())
		return firstNonEmpty(
			SessionIDFromContext(r.Context()),
			r.Header.Get(SessionIDHeader),
			r.Header.Get("X-Conversation-ID"),
			env.SessionID,
		)
	}
	env := audit.EnvelopeFromContext(ctx)
	return firstNonEmpty(SessionIDFromContext(ctx), env.SessionID)
}

func hiltBlockReason(status string, err error) string {
	switch status {
	case hiltStatusDenied:
		return "human approval denied"
	case hiltStatusTimeout:
		return "human approval timed out"
	case hiltStatusUnsupported:
		return "human approval unavailable"
	}
	if err != nil {
		return "human approval failed"
	}
	return "human approval not granted"
}

// NewGuardrailProxy constructs and wires a proxy. All provider routing is
// handled by the fetch interceptor's X-DC-Target-URL and X-AI-Auth headers.
// The conn parameter is the active connector for the configured agent framework;
// when non-nil, authentication and request signal extraction are delegated to it.
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
	conn connector.Connector,
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
	// Make config.yaml the single source of truth for HILT. The Rego policy
	// previously read `data.guardrail.hilt.*` from policies/rego/data.json,
	// which silently drifted out of sync with config.yaml whenever the
	// wizard updated one but not the other (see _sync_guardrail_hilt_to_opa
	// in cli/defenseclaw/commands/cmd_setup.py). Passing HILT through the
	// Rego `input` removes that coupling: finalize() now wires the live
	// config into every evaluation, and the policy prefers `input.hilt`
	// over `data.guardrail.hilt` (the data path is preserved as a fallback
	// for non-gateway callers like direct `opa eval` runs).
	inspector.SetHILTConfig(cfg.HILT.Enabled, cfg.HILT.MinSeverity)
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

	// Plan B2 / S0.2: synthesize a first-boot gateway token if none is
	// set. The previous "warn and trust loopback" path was a local-IDOR
	// risk — any process on the host could relay through the proxy.
	// EnsureGatewayToken is idempotent: the second call returns the
	// same value, so subsequent boots and the API server's parallel
	// init see identical tokens.
	gatewayToken, err := EnsureGatewayToken(dotenvPath)
	if err != nil {
		return nil, fmt.Errorf("gateway token: %w", err)
	}

	// Inject credentials into the connector so its Authenticate() method
	// can validate tokens without the proxy duplicating the logic.
	if conn != nil {
		conn.SetCredentials(gatewayToken, masterKey)
	}

	p := &GuardrailProxy{
		cfg:          cfg,
		logger:       logger,
		health:       health,
		otel:         otel,
		store:        store,
		dataDir:      dataDir,
		connector:    conn,
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

// SetConnectorSwitchState stores the registry and setup options so the proxy
// can hot-swap connectors at runtime when guardrail_runtime.json changes.
func (p *GuardrailProxy) SetConnectorSwitchState(reg *connector.Registry, opts connector.SetupOpts) {
	p.registry = reg
	p.setupOpts = opts
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
	// Layer 3 (observability): egress events reported back from the
	// TypeScript fetch-interceptor. Authenticated with the same
	// X-DC-Auth flow as every other proxy path.
	mux.HandleFunc("/v1/events/egress", p.handleEgressEvent)
	// Layer 4 (governance): the TypeScript fetch-interceptor fetches
	// the merged provider list (built-ins + ~/.defenseclaw/custom-providers.json)
	// at bootstrap so operators can extend coverage without rebuilding
	// the Go binary. Public — domain names are not secrets.
	mux.HandleFunc("/v1/config/providers", p.handleListProviders)
	// Operator trigger to reread the overlay at runtime after editing
	// custom-providers.json. Requires X-DC-Auth (same as every other
	// mutating endpoint) to prevent a hostile local process from
	// rolling the registry.
	mux.HandleFunc("/v1/config/providers/reload", p.handleReloadProviders)
	// Catch-all for provider-native paths (e.g. /v1/messages for Anthropic,
	// /v1beta/models/*/generateContent for Gemini). The fetch interceptor
	// preserves the original path; we inspect the content then forward verbatim
	// to the real upstream from X-DC-Target-URL.
	mux.HandleFunc("/", p.handlePassthrough)

	addr := guardrailListenAddr(p.cfg.Port, p.cfg.EffectiveHost())
	InstallSharedAgentRegistry("", strings.TrimSpace(p.defaultAgentName))
	// Strip /c/<connector>/ prefix so connector-routed traffic
	// (ANTHROPIC_BASE_URL=http://proxy/c/claudecode) hits the same
	// handlers as fetch-interceptor traffic.
	stripped := connectorPrefixStripper(mux, p.registry)
	limited := p.rateLimitMiddleware(stripped)
	logged := p.requestLogger(limited)
	// Middleware ordering matters for v7 correlation: request_id
	// must be in the context BEFORE CorrelationMiddleware freezes
	// the audit envelope, otherwise every audit row emitted from a
	// proxy request will have request_id=NULL. Outer→inner on the
	// actual request path is therefore:
	//   otel → requestID → correlation → requestLogger → rate → mux
	// which we construct by wrapping inside-out.
	withCorr := CorrelationMiddleware(SharedAgentRegistry())(logged)
	withRequestID := p.requestIDMiddleware(withCorr)
	handler := otelHTTPServerMiddleware("guardrail-proxy", withRequestID)
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

// connectorPrefixStripper strips /c/<connector-name>/ from the URL path so
// connector-routed traffic reaches the same handlers as fetch-interceptor
// traffic. For example, Claude Code sets ANTHROPIC_BASE_URL to
// http://proxy:4000/c/claudecode; the SDK then POSTs to
// /c/claudecode/v1/messages. This middleware rewrites that to /v1/messages.
//
// Security: the connector name must pass charset validation AND exist in
// the registry. Paths containing percent-encoded slashes (%2f/%2F) or
// dot-dot segments are rejected before any stripping occurs.
func connectorPrefixStripper(next http.Handler, reg *connector.Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path

		if strings.Contains(r.URL.RawPath, "%2f") || strings.Contains(r.URL.RawPath, "%2F") ||
			strings.Contains(r.URL.RawPath, "%5c") || strings.Contains(r.URL.RawPath, "%5C") {
			http.Error(w, "encoded path separators not allowed", http.StatusBadRequest)
			return
		}

		if strings.Contains(p, "..") {
			http.Error(w, "path traversal not allowed", http.StatusBadRequest)
			return
		}

		if strings.HasPrefix(p, "/c/") {
			if idx := strings.Index(p[3:], "/"); idx >= 0 {
				name := p[3 : 3+idx]
				if !isValidConnectorName(name) {
					http.Error(w, "invalid connector name", http.StatusBadRequest)
					return
				}
				if reg != nil {
					if _, ok := reg.Get(name); !ok {
						http.Error(w, "unknown connector", http.StatusNotFound)
						return
					}
				}
				r.URL.Path = p[3+idx:]
				r.URL.RawPath = ""
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isValidConnectorName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
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

	// Peek the body once so the shape classifier can run even when the
	// URL is unknown. 10 MiB cap matches the original io.Copy budget.
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	targetOrigin := r.Header.Get("X-DC-Target-URL")
	// Native-binary connectors (codex, zeptoclaw) can't inject
	// X-DC-Target-URL. Ask the active connector to resolve the
	// upstream from its provider snapshot before bailing.
	connForwardKey := ""
	if targetOrigin == "" {
		if connUpstream, connKey := hydrateConnectorSignals(p.connector, r, body); connUpstream != "" {
			targetOrigin = connUpstream
			connForwardKey = connKey
		}
	}
	if targetOrigin == "" {
		// No target URL from fetch interceptor or connector snapshot; reject.
		writeOpenAIError(w, http.StatusBadRequest, "missing X-DC-Target-URL header")
		return
	}
	if connForwardKey != "" && r.Header.Get("X-AI-Auth") == "" {
		r.Header.Set("X-AI-Auth", "Bearer "+connForwardKey)
	}

	// The fetch interceptor sets X-DC-Target-URL to the request origin only
	// (scheme://host). Rejoin the incoming request path so that path-prefixed
	// provider entries in providers.json (e.g. "chatgpt.com/backend-api") can
	// be matched correctly by the allowlist and the provider inference.
	targetForMatch := targetOrigin + r.URL.Path

	// Three-branch passthrough policy:
	//   known       → forward and audit as normal (legacy behavior)
	//   shape       → shape classifier says this is an LLM body but the
	//                 host is unknown; forward IFF
	//                 guardrail.allow_unknown_llm_domains=true, always
	//                 emit an egress event, never forward to a private /
	//                 link-local IP (SSRF defense in depth)
	//   passthrough → blocked outright; caller sees 403
	//
	// Every branch emits an EventEgress below so the operator can
	// tune the allowlist confidently. See internal/gateway/events.go.
	targetHost := ""
	if u, perr := url.Parse(targetOrigin); perr == nil {
		targetHost = u.Hostname()
	}
	branch := "passthrough"
	bodyShape := BodyShapeNone
	if isKnownProviderDomain(targetForMatch) {
		branch = "known"
	} else {
		if shape, ok := isLLMShapedBody(body); ok {
			bodyShape = shape
			branch = "shape"
		}
	}

	mkEgress := func(decision, reason string) gatewaylog.EgressPayload {
		return gatewaylog.EgressPayload{
			TargetHost:   targetHost,
			TargetPath:   r.URL.Path,
			BodyShape:    string(bodyShape),
			LooksLikeLLM: branch != "passthrough",
			Branch:       branch,
			Decision:     decision,
			Reason:       reason,
			Source:       "go",
		}
	}

	if branch == "passthrough" {
		fmt.Fprintf(os.Stderr, "[guardrail] BLOCKED passthrough to unknown domain: %s (path=%s)\n", targetOrigin, r.URL.Path)
		emitEgress(r.Context(), mkEgress("block", "unknown-host-no-shape"))
		writeOpenAIError(w, http.StatusForbidden, "target URL does not match any known LLM provider domain")
		return
	}

	if branch == "shape" {
		// SSRF defense-in-depth: never forward an LLM-shaped request
		// to a private / link-local IP even when AllowUnknownLLMDomains
		// is on. A malicious skill could point the LLM SDK at the cloud
		// IMDS endpoint (169.254.169.254) and happen to send a
		// `messages`-shaped body.
		if isPrivateHost(targetHost) {
			fmt.Fprintf(os.Stderr, "[guardrail] BLOCKED LLM-shaped passthrough to private IP: %s\n", targetHost)
			emitEgress(r.Context(), mkEgress("block", "private-ip"))
			writeOpenAIError(w, http.StatusForbidden, "target host resolves to a private address")
			return
		}
		allow := false
		if p.cfg != nil {
			allow = p.cfg.AllowUnknownLLMDomains
		}
		if !allow {
			fmt.Fprintf(os.Stderr, "[guardrail] BLOCKED shape-detected passthrough to unknown domain: %s (shape=%s)\n", targetHost, bodyShape)
			emitEgress(r.Context(), mkEgress("block", "allow-unknown-disabled"))
			writeOpenAIError(w, http.StatusForbidden, "target URL does not match any known LLM provider domain (set guardrail.allow_unknown_llm_domains to permit)")
			return
		}
		emitEgress(r.Context(), mkEgress("allow", "allow-unknown-enabled"))
	} else {
		emitEgress(r.Context(), mkEgress("allow", "known-provider"))
	}

	// Extract text for inspection. Parse multiple API formats:
	//  - Chat Completions: {"messages": [...]}
	//  - Anthropic Messages: {"messages": [...], "system": "..."}
	//  - OpenAI/Azure Responses API: {"input": [...] | "string", "instructions": "..."}
	//  - Gemini generateContent: {"contents": [{"role": "user", "parts": [{"text": "..."}]}], "systemInstruction": {...}}
	//  - Ollama /api/generate: {"prompt": "...", "system": "..."}
	var partial struct {
		Model             string          `json:"model"`
		Messages          []ChatMessage   `json:"messages"`
		System            string          `json:"system,omitempty"`
		Instructions      string          `json:"instructions,omitempty"` // Responses API system prompt
		Input             json.RawMessage `json:"input,omitempty"`        // Responses API
		Contents          json.RawMessage `json:"contents,omitempty"`     // Gemini native
		SystemInstruction json.RawMessage `json:"systemInstruction,omitempty"`
		Prompt            string          `json:"prompt,omitempty"` // Ollama /api/generate + legacy completion APIs
		Stream            bool            `json:"stream,omitempty"`
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
	// Gemini native (generateContent / streamGenerateContent): top-level
	// `contents[]` is an array of turns, each with `parts[]` holding the
	// actual text. Prior to this, Gemini-shaped bodies reached
	// handlePassthrough with userText == "" and bypassed pre-call
	// inspection entirely — a full policy bypass on Gemini's wire format.
	// Also pull systemInstruction as a fallback so Vertex flows that
	// only set a system prompt are still inspected.
	if userText == "" && len(partial.Contents) > 0 {
		if turns := extractGeminiContentsText(partial.Contents); len(turns) > 0 {
			// Build synthetic ChatMessages so downstream scanners
			// (Cisco AI Defense, judge) see realistic conversation
			// shape instead of a single blob.
			geminiMsgs := make([]ChatMessage, 0, len(turns))
			for _, t := range turns {
				role := t.Role
				if role == "model" {
					role = "assistant"
				}
				if role == "" {
					role = "user"
				}
				geminiMsgs = append(geminiMsgs, ChatMessage{Role: role, Content: t.Text})
			}
			userText = lastUserText(geminiMsgs)
			if len(partial.Messages) == 0 {
				partial.Messages = geminiMsgs
			}
		}
	}
	if userText == "" && len(partial.SystemInstruction) > 0 {
		userText = extractGeminiSystemInstructionText(partial.SystemInstruction)
	}

	// Ollama /api/generate + legacy completion endpoints: top-level
	// `prompt` is a single string. Inspect it like any user turn so
	// direct Ollama clients are not a bypass route.
	if userText == "" && partial.Prompt != "" {
		userText = partial.Prompt
	}

	// Responses API: fall back to instructions (system-level prompt) if no
	// user turn was found — still worth inspecting for prompt injection.
	if userText == "" && partial.Instructions != "" {
		userText = partial.Instructions
	}

	passthroughPromptID := ""
	passthroughReqForTelemetry := ChatRequest{Model: partial.Model, RawBody: body}
	if passthroughReqForTelemetry.Model == "" {
		passthroughReqForTelemetry.Model = label
	}
	inspectionText := promptInspectionText(userText)
	if userText != "" &&
		!isHeartbeatMessage(inspectionText, partial.Messages) &&
		!isSessionStartupMessage(inspectionText) {
		meta := proxyLLMEventMeta(p, r, &passthroughReqForTelemetry, provider)
		meta.PromptID = stableLLMEventID("prompt", meta.Source, meta.SessionID, meta.RequestID, label)
		passthroughPromptID = emitLLMPromptEvent(r.Context(), meta, userText, body)

		t0 := time.Now()
		verdict := p.inspector.Inspect(r.Context(), "prompt", inspectionText, partial.Messages, label, mode)
		p.resolveConfirm(r.Context(), r, verdict, "prompt", label, mode)
		elapsed := time.Since(t0)
		p.logPreCall(label, partial.Messages, verdict, elapsed)
		p.recordTelemetry(r.Context(), "prompt", label, verdict, elapsed, nil, nil,
			rawTelemetryField{key: "raw_request_body", raw: body})
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
			// the agent surfaces it to the user rather than treating it as
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

	// Copy all original headers except proxy-hop, auth, and internal
	// DefenseClaw correlation headers.
	//
	//   - Auth headers (Authorization, x-api-key, api-key) are stripped to
	//     avoid duplicates — the resolved upstreamAuth is set as the single
	//     canonical Authorization header below.
	//   - Content-Length is stripped because notification injection can
	//     change the body size; upstreamReq.ContentLength is the
	//     authoritative value (set above) and the Go http client writes
	//     the correct header automatically.
	//   - Internal DefenseClaw correlation headers (x-dc-*, x-defenseclaw-*)
	//     MUST NOT leak to third-party LLM providers — they carry session,
	//     agent, policy, and destination identifiers that are internal
	//     metadata, and echoing them in provider logs creates a privacy
	//     and operational-security regression.
	//   - W3C trace context (traceparent/tracestate) is also internal and
	//     not meaningful to upstream providers; strip to avoid cross-tenant
	//     trace correlation leakage.
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		switch lk {
		case "x-dc-target-url", "x-ai-auth", "x-dc-auth", "host",
			"authorization", "x-api-key", "api-key", "content-length",
			"traceparent", "tracestate":
			continue
		}
		if strings.HasPrefix(lk, "x-dc-") || strings.HasPrefix(lk, "x-defenseclaw-") {
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
		responseReqForTelemetry := ChatRequest{Model: passthroughReqForTelemetry.Model, RawBody: body}
		responseMeta := proxyLLMEventMeta(p, r, &responseReqForTelemetry, provider)
		responseMeta.PromptID = passthroughPromptID
		responseMeta.ResponseID = firstNonEmpty(responseIDFromRawJSON(respBody), stableLLMEventID("response", responseMeta.Source, responseMeta.SessionID, responseMeta.RequestID, label))
		emitLLMResponseEvent(r.Context(), responseMeta, content, string(respBody), nil)

		if content != "" {
			postCtx, postCancel := p.postCallContext(r.Context())
			t0 := time.Now()
			respMessages := []ChatMessage{{Role: "assistant", Content: content}}
			verdict := p.inspector.Inspect(postCtx, "completion", content, respMessages, label, mode)
			postCancel()
			p.resolveConfirm(r.Context(), r, verdict, "completion", label, mode)
			elapsed := time.Since(t0)
			p.logPostCall(label, content, verdict, elapsed, nil)
			p.recordTelemetry(r.Context(), "completion", label, verdict, elapsed, nil, nil,
				rawTelemetryField{key: "raw_response_body", raw: respBody})

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
				p.resolveConfirm(r.Context(), r, initVerdict, "completion", label, mode)
				if initVerdict.Severity != "NONE" && initVerdict.Action == "block" {
					fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-PREBLOCK severity=%s %s (blocked before any output sent to client)\n",
						initVerdict.Severity, redaction.Reason(initVerdict.Reason))
					p.recordTelemetry(r.Context(), "completion", label, initVerdict, 0, nil, nil,
						rawTelemetryString("raw_response_content", accumulated.String()))
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
						p.resolveConfirm(r.Context(), r, midVerdict, "completion", label, mode)
						if midVerdict.Severity != "NONE" && midVerdict.Action == "block" {
							fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-BLOCK severity=%s %s (WARNING: %d bytes already forwarded to client)\n",
								midVerdict.Severity, redaction.Reason(midVerdict.Reason), lastScanLen+len(chunk))
							p.recordTelemetry(r.Context(), "completion", label, midVerdict, 0, nil, nil,
								rawTelemetryString("raw_response_content", accumulated.String()))
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
			responseReqForTelemetry := ChatRequest{Model: passthroughReqForTelemetry.Model, RawBody: body}
			responseMeta := proxyLLMEventMeta(p, r, &responseReqForTelemetry, provider)
			responseMeta.PromptID = passthroughPromptID
			responseMeta.ResponseID = stableLLMEventID("response", responseMeta.Source, responseMeta.SessionID, responseMeta.RequestID, label)
			emitLLMResponseEvent(r.Context(), responseMeta, content, content, nil)

			postCtx, postCancel := p.postCallContext(r.Context())
			t0 := time.Now()
			respMessages := []ChatMessage{{Role: "assistant", Content: content}}
			verdict := p.inspector.Inspect(postCtx, "completion", content, respMessages, label, mode)
			postCancel()
			p.resolveConfirm(r.Context(), r, verdict, "completion", label, mode)
			elapsed := time.Since(t0)
			p.logPostCall(label, content, verdict, elapsed, nil)
			p.recordTelemetry(r.Context(), "completion", label, verdict, elapsed, nil, nil,
				rawTelemetryString("raw_response_content", content))
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
// Some agent frameworks probe this endpoint before sending chat completion
// requests.
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

// providerRegistryMu guards providerDomains / ollamaPorts / providerRegistry.
// The registry can be rebuilt at runtime via ReloadProviderRegistry() when
// the operator overlay at ~/.defenseclaw/custom-providers.json changes.
var providerRegistryMu sync.RWMutex

// providerDomains is built at init (and on reload) from the embedded
// providers.json merged with the operator overlay. Each entry maps a
// domain substring to the provider name.
var providerDomains []providerDomainEntry

type providerDomainEntry struct {
	domain string
	name   string
}

// ollamaPorts lists the TCP ports that Ollama binds to (from providers.json).
// Requests to localhost/127.0.0.1/::1 on these ports are treated as known
// provider traffic so the SSRF allowlist does not reject them.
var ollamaPorts []int

// providerRegistry holds the merged provider list (built-ins + overlay)
// as last loaded, for serving GET /v1/config/providers.
var providerRegistry *configs.ProvidersConfig

func init() {
	if err := ReloadProviderRegistry(); err != nil {
		panic("gateway: failed to load embedded providers.json: " + err.Error())
	}
}

// ReloadProviderRegistry re-reads the embedded providers.json and merges
// the operator overlay at ~/.defenseclaw/custom-providers.json. Safe to
// call at runtime; concurrent readers of providerDomains / ollamaPorts
// see a consistent snapshot.
func ReloadProviderRegistry() error {
	cfg, err := configs.LoadProviders()
	if err != nil {
		return err
	}
	domains := make([]providerDomainEntry, 0, len(cfg.Providers)*2)
	for _, p := range cfg.Providers {
		for _, d := range p.Domains {
			domains = append(domains, providerDomainEntry{domain: d, name: p.Name})
		}
	}
	providerRegistryMu.Lock()
	providerDomains = domains
	ollamaPorts = cfg.OllamaPorts
	providerRegistry = cfg
	providerRegistryMu.Unlock()
	return nil
}

// providerRegistrySnapshot returns the currently-loaded provider list
// under the read lock. The returned slice is safe to iterate but not to
// mutate.
func providerRegistrySnapshot() (*configs.ProvidersConfig, []providerDomainEntry, []int) {
	providerRegistryMu.RLock()
	defer providerRegistryMu.RUnlock()
	return providerRegistry, providerDomains, ollamaPorts
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
	providerRegistryMu.RLock()
	domains := providerDomains
	providerRegistryMu.RUnlock()
	for _, pd := range domains {
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
// model and API key. This handles the direct-provider case where the agent is
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

// hydrateConnectorSignals lets a connector whose agent has no fetch
// interceptor (native binaries like ZeptoClaw) supply the upstream URL and
// provider key that X-DC-Target-URL / X-AI-Auth would otherwise carry.
// Returning ("", "") means "no opinion" — the caller must leave req.TargetURL
// / req.TargetAPIKey alone so fetch-interceptor paths still work.
func hydrateConnectorSignals(conn connector.Connector, r *http.Request, body []byte) (string, string) {
	if conn == nil {
		return "", ""
	}
	cs, err := conn.Route(r, body)
	if err != nil || cs == nil {
		return "", ""
	}
	return cs.RawUpstream, cs.RawAPIKey
}

// resolveProviderFromHeaders selects the upstream LLMProvider for the given
// request. The fetch interceptor sets X-DC-Target-URL on every outbound LLM
// call; we infer the provider from that URL and use X-AI-Auth as the API key.
//
// Fallback: when X-DC-Target-URL is absent (direct-provider mode, where the
// agent routes to the guardrail proxy as a custom provider endpoint), use the
// configured guardrail model and API key.
func (p *GuardrailProxy) resolveProviderFromHeaders(req *ChatRequest) LLMProvider {
	if req.TargetURL == "" {
		return p.resolveConfiguredProvider(req)
	}

	prefix := inferProviderFromURL(req.TargetURL + req.TargetPath)
	if prefix == "" {
		return nil
	}

	// Azure requires the specific resource endpoint as baseURL.
	// Bedrock (ZeptoClaw / OpenClaw) uses regional bedrock-runtime URLs with
	// ABSK bearer keys — Bifrost handles that path; pin BaseURL to the snapshot
	// origin so the tenant routes to the correct region.
	baseURL := ""
	if prefix == "azure" {
		baseURL = req.TargetURL
	}
	if prefix == "bedrock" {
		baseURL = strings.TrimRight(req.TargetURL, "/")
	}

	modelArg := compositeModelForUpstream(prefix, req.Model)
	provider, err := NewProviderWithBase(modelArg, req.TargetAPIKey, baseURL)
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
		redactAuthValue(r.Header.Get("Authorization")),
		redactAuthValue(r.Header.Get("api-key")),
		scrubURLSecrets(r.Header.Get("X-DC-Target-URL")))
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

	// Native-binary connectors (zeptoclaw) have no fetch interceptor, so the
	// request arrives without X-DC-Target-URL / X-AI-Auth. Ask the active
	// connector to resolve them from its captured config snapshot. Existing
	// header values win — fetch-interceptor paths are unchanged.
	if connUpstream, connKey := hydrateConnectorSignals(p.connector, r, body); connUpstream != "" {
		if req.TargetURL == "" {
			req.TargetURL = connUpstream
		}
		if req.TargetAPIKey == "" {
			req.TargetAPIKey = connKey
		}
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
	// agent plugins) hit this code path, and they suffer the same
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
			conversationID, agentName, agentName, p.agentIDForRequest(), "",
		)
	}
	if agentCtx == nil {
		agentCtx = context.Background()
	}

	// --- Pre-call inspection (apply_guardrail input, child of invoke_agent) ---
	userText := lastUserText(req.Messages)
	_, promptProviderName := p.llmSystemAndProvider(req.Model)
	promptID := ""
	inspectionText := promptInspectionText(userText)
	if userText != "" &&
		!isHeartbeatMessage(inspectionText, req.Messages) &&
		!isSessionStartupMessage(inspectionText) {
		meta := proxyLLMEventMeta(p, r, &req, promptProviderName)
		meta.PromptID = stableLLMEventID("prompt", meta.Source, meta.SessionID, meta.RequestID, req.Model)
		promptID = emitLLMPromptEvent(r.Context(), meta, userText, req.RawBody)

		t0 := time.Now()

		// Start guardrail span for input inspection.
		var grSpan trace.Span
		if p.otel != nil {
			_, grSpan = p.otel.StartGuardrailSpan(
				agentCtx,
				"defenseclaw", "input", req.Model,
			)
		}

		verdict := p.inspector.Inspect(r.Context(), "prompt", inspectionText, req.Messages, req.Model, mode)
		p.resolveConfirm(r.Context(), r, verdict, "prompt", req.Model, mode)
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
		p.recordTelemetry(r.Context(), "prompt", req.Model, verdict, elapsed, nil, nil,
			rawTelemetryField{key: "raw_request_body", raw: req.RawBody})

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

	// For fetch-intercepted OpenAI-compatible requests, preserve the
	// original request body when forwarding to the real upstream. This is
	// required because provider-specific extension fields such as
	// chat_template_kwargs, extra_body, and parallel_tool_calls must not be
	// dropped by the structured provider translation path.
	if req.TargetURL != "" {
		p.rawForwardChatCompletion(w, r, body, &req)
		return
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
		p.handleStreamingRequest(w, r, &req, mode, customBlockMsg, upstream, agentCtx, promptID)
	} else {
		p.handleNonStreamingRequest(w, r, &req, mode, customBlockMsg, upstream, agentCtx, promptID)
	}

	// End invoke_agent span after the full request completes.
	if p.otel != nil && agentSpan != nil {
		p.otel.EndAgentSpan(agentSpan, "")
	}
}

func (p *GuardrailProxy) handleNonStreamingRequest(w http.ResponseWriter, r *http.Request, req *ChatRequest, mode, customBlockMsg string, upstream LLMProvider, agentCtx context.Context, promptID string) {
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
		p.otel.SetRawSpanString(llmSpan, "defenseclaw.llm.request.body", string(req.RawBody))
	}

	resp, err := upstream.ChatCompletion(r.Context(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] upstream error: %v\n", err)
		if p.otel != nil && llmSpan != nil {
			p.otel.EndLLMSpan(llmSpan, aliasModel, 0, 0, []string{"error"}, 0, "none", "", system, llmStartTime, p.connectorName(), p.connectorName(), p.agentIDForRequest())
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
	if p.otel != nil && llmSpan != nil {
		p.otel.SetRawSpanString(llmSpan, "defenseclaw.llm.response.body", string(resp.RawResponse))
	}
	responseMeta := proxyLLMEventMeta(p, r, req, providerName)
	responseMeta.PromptID = promptID
	responseMeta.ResponseID = firstNonEmpty(resp.ID, stableLLMEventID("response", responseMeta.Source, responseMeta.SessionID, responseMeta.RequestID, req.Model))
	emitLLMResponseEvent(r.Context(), responseMeta, content, string(resp.RawResponse), finishReasons)

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
		postCancel()
		p.resolveConfirm(r.Context(), r, verdict, "completion", aliasModel, mode)
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
		p.recordTelemetry(r.Context(), "completion", aliasModel, verdict, elapsed, tokIn, tokOut,
			rawTelemetryField{key: "raw_response_body", raw: resp.RawResponse})

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
				p.otel.EndLLMSpan(llmSpan, aliasModel, promptTok, completionTok, finishReasons, toolCallCount, guardrail, "blocked", system, llmStartTime, p.connectorName(), p.connectorName(), p.agentIDForRequest())
			}
			msg := blockMessage(customBlockMsg, "completion", verdict.Reason)
			p.enqueueBlockNotification(verdict, "completion", aliasModel)
			p.writeBlockedResponse(w, aliasModel, msg)
			return
		}
	}

	// --- Post-call inspection: tool call arguments ---
	if len(resp.Choices) > 0 && resp.Choices[0].Message != nil {
		if verdict := p.inspectToolCalls(r.Context(), resp.Choices[0].Message.ToolCalls); verdict != nil {
			p.recordTelemetry(r.Context(), "tool-call", aliasModel, verdict, 0, nil, nil,
				rawTelemetryField{key: "raw_tool_calls", raw: resp.Choices[0].Message.ToolCalls})
			if verdict.Action == "block" && mode == "action" {
				if p.otel != nil && llmSpan != nil {
					promptTok, completionTok := 0, 0
					if resp.Usage != nil {
						promptTok = int(resp.Usage.PromptTokens)
						completionTok = int(resp.Usage.CompletionTokens)
					}
					p.otel.EndLLMSpan(llmSpan, aliasModel, promptTok, completionTok, finishReasons, toolCallCount, "local", "blocked", system, llmStartTime, p.connectorName(), p.connectorName(), p.agentIDForRequest())
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
	if len(resp.Choices) > 0 && resp.Choices[0].Message != nil {
		emitOpenAIToolCallEvents(r.Context(), responseMeta, resp.Choices[0].Message.ToolCalls)
	}

	// End LLM span with response data.
	if p.otel != nil && llmSpan != nil {
		promptTok, completionTok := 0, 0
		if resp.Usage != nil {
			promptTok = int(resp.Usage.PromptTokens)
			completionTok = int(resp.Usage.CompletionTokens)
		}
		p.otel.EndLLMSpan(llmSpan, aliasModel, promptTok, completionTok, finishReasons, toolCallCount, guardrail, guardrailResult, system, llmStartTime, p.connectorName(), p.connectorName(), p.agentIDForRequest())
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

func (p *GuardrailProxy) handleStreamingRequest(w http.ResponseWriter, r *http.Request, req *ChatRequest, mode, customBlockMsg string, upstream LLMProvider, agentCtx context.Context, promptID string) {
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
		p.otel.SetRawSpanString(llmSpan, "defenseclaw.llm.request.body", string(req.RawBody))
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
			p.resolveConfirm(r.Context(), r, midVerdict, "completion", aliasModel, mode)
			if midVerdict.Severity != "NONE" && midVerdict.Action == "block" {
				fmt.Fprintf(os.Stderr, "[guardrail] STREAM-BLOCK severity=%s %s\n",
					midVerdict.Severity, redaction.Reason(midVerdict.Reason))
				p.recordTelemetry(r.Context(), "completion", aliasModel, midVerdict, 0, nil, nil,
					rawTelemetryString("raw_response_content", accumulated.String()))
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
			p.resolveConfirm(r.Context(), r, initVerdict, "completion", aliasModel, mode)
			if initVerdict.Severity != "NONE" && initVerdict.Action == "block" {
				fmt.Fprintf(os.Stderr, "[guardrail] STREAM-PREBLOCK severity=%s %s\n",
					initVerdict.Severity, redaction.Reason(initVerdict.Reason))
				p.recordTelemetry(r.Context(), "completion", aliasModel, initVerdict, 0, nil, nil,
					rawTelemetryString("raw_response_content", accumulated.String()))
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
			p.otel.EndLLMSpan(llmSpan, aliasModel, 0, 0, []string{"error"}, 0, "none", "", system, llmStartTime, p.connectorName(), p.connectorName(), p.agentIDForRequest())
			llmSpan = nil
		}
	}

	guardrail := "none"
	guardrailResult := ""

	if streamBlocked {
		sseOutcome = "blocked"
		blockedMeta := proxyLLMEventMeta(p, r, req, providerName)
		blockedMeta.PromptID = promptID
		blockedMeta.ResponseID = stableLLMEventID("response", blockedMeta.Source, blockedMeta.SessionID, blockedMeta.RequestID, req.Model, "blocked")
		emitLLMResponseEvent(r.Context(), blockedMeta, accumulated.String(), accumulated.String(), append(streamFinishReasons, "blocked"))
		if p.otel != nil && llmSpan != nil {
			p.otel.EndLLMSpan(llmSpan, aliasModel, 0, 0, append(streamFinishReasons, "blocked"), 0, "local", "block", system, llmStartTime, p.connectorName(), p.connectorName(), p.agentIDForRequest())
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
		postCancel()
		p.resolveConfirm(r.Context(), r, verdict, "completion", aliasModel, mode)
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
		p.recordTelemetry(r.Context(), "completion", aliasModel, verdict, elapsed, tokIn, tokOut,
			rawTelemetryString("raw_response_content", content))

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
	streamResponseMeta := proxyLLMEventMeta(p, r, req, providerName)
	streamResponseMeta.PromptID = promptID
	streamResponseMeta.ResponseID = stableLLMEventID("response", streamResponseMeta.Source, streamResponseMeta.SessionID, streamResponseMeta.RequestID, req.Model)
	emitLLMResponseEvent(r.Context(), streamResponseMeta, accumulated.String(), accumulated.String(), streamFinishReasons)
	if len(assembledTC) > 0 {
		if verdict := p.inspectToolCalls(r.Context(), assembledTC); verdict != nil {
			p.recordTelemetry(r.Context(), "tool-call", aliasModel, verdict, 0, nil, nil,
				rawTelemetryField{key: "raw_tool_calls", raw: assembledTC})
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
		emitOpenAIToolCallEvents(r.Context(), streamResponseMeta, assembledTC)
	}

	if p.otel != nil && llmSpan != nil {
		promptTok, completionTok := 0, 0
		if usage != nil {
			promptTok = int(usage.PromptTokens)
			completionTok = int(usage.CompletionTokens)
		}
		p.otel.SetRawSpanString(llmSpan, "defenseclaw.llm.response.content", accumulated.String())
		p.otel.SetRawSpanString(llmSpan, "defenseclaw.llm.tool_calls", string(assembledTC))
		p.otel.EndLLMSpan(llmSpan, aliasModel, promptTok, completionTok, streamFinishReasons, toolCallCount, guardrail, guardrailResult, system, llmStartTime, p.connectorName(), p.connectorName(), p.agentIDForRequest())
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
//
// Dispatch order:
//
//  1. Bedrock is provider-specific (binary eventstream framing, AWS Sigv4
//     auth) and predates the FormatAdapter registry — it keeps its own
//     branch so #124's proxy_bedrock_block.go handler stays the single
//     source of truth for Bedrock wire formats.
//  2. The FormatAdapter registry is consulted next. An adapter that
//     claims the path owns the full block envelope (non-stream + stream)
//     and the provider hint is ignored — path-based routing is the more
//     reliable signal when the fetch interceptor sets X-DC-Target-URL but
//     leaves the provider hint unset.
//  3. Fallback is the OpenAI Chat Completions writer, which is what we
//     always returned before the registry existed. Adding new wire
//     formats should go through the registry, not through more branches
//     here.
func (p *GuardrailProxy) writeBlockedPassthrough(w http.ResponseWriter, path, provider, model string, stream bool, msg string) {
	if provider == "bedrock" {
		// Bedrock decides streaming vs non-streaming from the URL path
		// (/converse-stream vs /converse, /invoke-with-response-stream
		// vs /invoke) rather than a `stream: true` body field, so the
		// passthrough dispatcher re-derives it there. The AWS SDK on
		// the client side expects `application/vnd.amazon.eventstream`
		// binary framing for streaming endpoints and fails to parse
		// plain OpenAI-style SSE as produced by writeBlockedStream,
		// surfacing "Truncated event message received" to the caller.
		p.writeBlockedPassthroughBedrock(w, path, model, msg)
		return
	}
	if a := adapterFor(path, provider); a != nil {
		a.WriteBlockResponse(p, w, path, model, stream, msg)
		return
	}
	// Legacy fallback: any path the registry didn't claim lands on the
	// Chat Completions writer (preserves pre-v7 behavior for unknown
	// providers). New formats MUST be added as registry entries.
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

// writeBlockedStreamGemini returns a blocked response as a Gemini
// streamGenerateContent SSE stream. The Google GenAI client library
// (both JS and Python) parses `data:` frames whose payload is the same
// `candidates[]` envelope returned by the non-stream variant. Gemini's
// own server emits one frame per chunk followed by a sentinel; since
// we're returning a single short block message, we emit exactly one
// frame with finishReason=SAFETY and let the client close the stream.
//
// When w doesn't support http.Flusher (recorder-based tests) we fall
// back to the non-stream response so clients still see the block
// banner rather than an EOF halfway through the stream.
func (p *GuardrailProxy) writeBlockedStreamGemini(w http.ResponseWriter, msg string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		p.writeBlockedResponseGemini(w, msg)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-DefenseClaw-Blocked", "true")
	w.WriteHeader(http.StatusOK)

	frame := map[string]interface{}{
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
	data, _ := json.Marshal(frame)
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
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
//   - If gatewayToken is configured (DEFENSECLAW_GATEWAY_TOKEN), we require it on
//     ALL connections — including loopback — so that a rogue local process
//     cannot use the proxy as an open relay to LLM providers.
//   - If gatewayToken is NOT configured (legacy / first-run), loopback is
//     trusted unconditionally to avoid breaking existing setups. A warning is
//     logged at startup (see NewGuardrailProxy).
//   - For non-loopback (sandbox / bridge deployments), authentication is always
//     required via X-DC-Auth or the master key.

func (p *GuardrailProxy) authenticateRequest(w http.ResponseWriter, r *http.Request) bool {
	// Test-only fast path: legacy proxy_test.go fixtures construct
	// a GuardrailProxy directly without the NewGuardrailProxy boot
	// path that synthesizes the gateway token. The bypass is set
	// only by newTestProxy in this package.
	if p.skipAuthForTest {
		return true
	}
	// Delegate to the connector when available — each connector knows its
	// own auth scheme (tokens, loopback trust, etc.).
	if p.connector != nil {
		if p.connector.Authenticate(r) {
			return true
		}
		reason := "invalid_token"
		if strings.TrimSpace(r.Header.Get("X-DC-Auth")) == "" && (p.masterKey == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")) {
			reason = "missing_token"
		}
		p.emitProxyAuthFailure(r, reason)
		return false
	}

	// Fallback: built-in auth for when no connector is wired (tests, legacy).
	if dcAuth := r.Header.Get("X-DC-Auth"); dcAuth != "" {
		token := strings.TrimPrefix(dcAuth, "Bearer ")
		if p.gatewayToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(p.gatewayToken)) == 1 {
			return true
		}
	}

	if p.masterKey != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") && subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(p.masterKey)) == 1 {
			return true
		}
	}

	// Plan B2 / S0.2: no longer fall through to loopback-trust when the
	// gateway token is empty. EnsureGatewayToken synthesizes one at boot
	// if the operator hasn't supplied one, so this case is unreachable
	// in production. If we somehow got here with an empty token, the
	// safe behavior is fail-closed: a misconfigured proxy should refuse
	// traffic, not silently accept it.
	if p.gatewayToken == "" {
		p.emitProxyAuthFailure(r, "no_token_configured")
		return false
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
// file using PBKDF2-SHA256 with 100k iterations.
//
// PR #141 audit H9: the previous implementation was a single HMAC-SHA256
// round. With ~16 bytes of effective entropy in `device.key` and zero
// stretching, a leak of `device.key` (a 0600 file in dataDir, but anyone
// with that fd has full master-key control) was instantly equivalent to
// a master-key compromise — and a leak of the master key gave the
// attacker an `Authorization: Bearer sk-dc-…` that bypasses the entire
// connector auth chain (see Codex/ZeptoClaw Authenticate). PBKDF2 with
// 100k iterations puts a CPU cost on each crack attempt, so an attacker
// needs the live file plus seconds-per-guess of compute even when both
// the device.key contents and the salt are known.
//
// BREAKING for any persisted `sk-dc-…` value derived under the old
// algorithm: those will no longer match the master key the proxy
// recomputes at boot. Operators who cached the literal string need to
// re-read it from the running proxy (the value is logged once at boot
// to gateway.log) or, more commonly, simply continue using whichever
// connector-issued bearer their tooling has — `sk-dc-` master keys are
// an internal fallback, not the supported credential.
func deriveMasterKey(dataDir string) string {
	keyFile := filepath.Join(dataDir, "device.key")
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return ""
	}
	// 32-byte output (= 64 hex chars) — wider than the previous
	// truncated-to-16-byte digest so a brute-force attacker now also
	// needs to cover a meaningfully larger search space if they ever
	// recover only the published `sk-dc-…` string.
	dk := pbkdf2.Key(data, []byte("defenseclaw-proxy-master-key"), 100_000, 32, sha256.New)
	return "sk-dc-" + fmt.Sprintf("%x", dk)
}

// ---------------------------------------------------------------------------
// Runtime config hot-reload
// ---------------------------------------------------------------------------

var (
	runtimeCacheMu sync.Mutex
	runtimeCache   map[string]any
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

	// Decode into map[string]any so heterogeneous value types
	// (string for mode, bool for hilt_enabled, etc.) round-trip
	// without breaking the whole reload. The Python writer in
	// cli/defenseclaw/commands/cmd_setup.py::_write_guardrail_runtime
	// owns the wire schema; per-key extraction below validates each
	// field independently so a future schema addition can't poison
	// existing fields.
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		runtimeCache = nil
		runtimeCacheTs = time.Now()
		return
	}

	runtimeCache = cfg
	runtimeCacheTs = time.Now()
	p.applyRuntime(cfg)
}

// runtimeString extracts a string value from the heterogeneous runtime
// cache and reports whether the caller should treat it as set. We
// intentionally treat absent keys, non-string values, and empty
// strings as "not provided" so the caller's `_, ok := cfg["x"]; if ok`
// logic keeps working even when a future schema bump adds a new key
// type that isn't representable as a string.
func runtimeString(cfg map[string]any, key string) (string, bool) {
	raw, ok := cfg[key]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// runtimeBool extracts a bool value from the runtime cache. JSON's bool
// can't decode into a string, so we accept either a real bool or the
// canonical string forms ("true"/"false") for forward compatibility
// with future serializers. Anything else is treated as absent so a
// malformed value can't accidentally flip a sensitive toggle.
func runtimeBool(cfg map[string]any, key string) (bool, bool) {
	raw, ok := cfg[key]
	if !ok {
		return false, false
	}
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func (p *GuardrailProxy) applyRuntime(cfg map[string]any) {
	p.rtMu.Lock()
	defer p.rtMu.Unlock()

	if m, ok := runtimeString(cfg, "mode"); ok && (m == "observe" || m == "action") {
		p.mode = m
	}
	if sm, ok := runtimeString(cfg, "scanner_mode"); ok && (sm == "local" || sm == "remote" || sm == "both") {
		p.inspector.SetScannerMode(sm)
	}
	if bm, ok := runtimeString(cfg, "block_message"); ok {
		p.blockMessage = bm
	}
	if newName, ok := runtimeString(cfg, "connector"); ok {
		p.switchConnectorLocked(newName)
	}

	// HILT hot-reload. The inspector caches the HILT view that the
	// Rego policy reads as `input.hilt`; without re-applying it here
	// an operator who flips guardrail.hilt.enabled in config.yaml (or
	// runs ``defenseclaw config set guardrail.hilt.enabled ...``)
	// keeps the boot-time value until the next sidecar restart. Both
	// fields must be present together — a partial update (just one
	// of the two) would let a half-edited runtime file rotate the
	// inspector into an unintended state, so we only re-sync when
	// hilt_enabled is explicitly set.
	if enabled, ok := runtimeBool(cfg, "hilt_enabled"); ok {
		minSev, _ := runtimeString(cfg, "hilt_min_severity")
		p.inspector.SetHILTConfig(enabled, minSev)
	}
}

// switchConnectorLocked tears down the current connector and sets up the
// new one. Must be called with rtMu held.
func (p *GuardrailProxy) switchConnectorLocked(newName string) {
	if p.registry == nil {
		return
	}
	if p.connector != nil && p.connector.Name() == newName {
		return
	}
	newConn, ok := p.registry.Get(newName)
	if !ok {
		fmt.Fprintf(os.Stderr, "[guardrail] runtime connector switch: %q not in registry — ignoring\n", newName)
		return
	}

	ctx := context.Background()
	oldConn := p.connector

	newConn.SetCredentials(p.gatewayToken, p.masterKey)

	if oldConn != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] runtime connector switch: tearing down %s\n", oldConn.Name())
		if err := oldConn.Teardown(ctx, p.setupOpts); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] teardown %s: %v\n", oldConn.Name(), err)
		}
		if err := oldConn.VerifyClean(p.setupOpts); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: %s teardown left stale state: %v\n", oldConn.Name(), err)
		}
	}

	fmt.Fprintf(os.Stderr, "[guardrail] runtime connector switch: setting up %s\n", newName)
	if err := newConn.Setup(ctx, p.setupOpts); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] setup %s failed: %v — rolling back to %s\n", newName, err, oldConn.Name())
		if oldConn != nil {
			if reErr := oldConn.Setup(ctx, p.setupOpts); reErr != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] rollback setup %s also failed: %v\n", oldConn.Name(), reErr)
			}
		}
		return
	}

	p.connector = newConn
	if err := connector.SaveActiveConnector(p.setupOpts.DataDir, newName); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] save active connector state: %v\n", err)
	}

	if p.health != nil {
		p.health.SetConnector(newConn.Name(), newConn.ToolInspectionMode(), newConn.SubprocessPolicy())
	}
	fmt.Fprintf(os.Stderr, "[guardrail] runtime connector switch complete: %s (%s)\n", newConn.Name(), newConn.Description())
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

// redactAuthValue masks an Authorization or api-key header value for safe
// logging. Shows only the prefix (e.g. "Bearer") and the last 4 chars of
// the credential, or "[empty]" / "[set]" for short values.
func redactAuthValue(val string) string {
	if val == "" {
		return "[empty]"
	}
	parts := strings.SplitN(val, " ", 2)
	if len(parts) == 2 {
		scheme := parts[0]
		cred := parts[1]
		if len(cred) > 8 {
			return scheme + " ****" + cred[len(cred)-4:]
		}
		return scheme + " [set]"
	}
	if len(val) > 8 {
		return "****" + val[len(val)-4:]
	}
	return "[set]"
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
	if err != nil {
		return false
	}
	providerRegistryMu.RLock()
	ports := ollamaPorts
	providerRegistryMu.RUnlock()
	if len(ports) == 0 {
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
	for _, op := range ports {
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
	providerRegistryMu.RLock()
	domains := providerDomains
	providerRegistryMu.RUnlock()
	for _, pd := range domains {
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

func (p *GuardrailProxy) recordTelemetry(ctx context.Context, direction, model string, verdict *ScanVerdict, elapsed time.Duration, tokIn, tokOut *int64, rawFields ...rawTelemetryField) {
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
	details = appendRawTelemetryFields(details, rawFields...)

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
		//
		// PR #141 audit M5: route the persisted Details string
		// through redaction.ForSinkReason. The proxy composes
		// `details` from the verdict's reason/findings, which are
		// the literal matched substrings (e.g. a credit card or
		// API key fragment that triggered the rule). The TUI is
		// fine to render these — operators have local intent —
		// but third-party sinks (Splunk forwarder, Loki, Cisco
		// AID telemetry) inheriting from this row must not.
		// LogActionCtx above already honors the same redaction
		// contract via the logger's sink chain; this brings the
		// store-direct path to parity instead of leaking the
		// unredacted form to whichever forwarder reads from
		// audit.Store.
		evt := audit.Event{
			Action:    "guardrail-inspection",
			Target:    model,
			Severity:  verdict.Severity,
			Details:   redaction.ForSinkReason(details),
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
		p.otel.RecordGuardrailEvaluation(ctx, p.connectorName()+":guardrail-proxy", verdict.Action)
		p.otel.RecordGuardrailLatency(ctx, p.connectorName()+":guardrail-proxy", elapsedMs)
		if verdict.CiscoElapsedMs > 0 {
			p.otel.RecordGuardrailLatency(ctx, "cisco-ai-defense", verdict.CiscoElapsedMs)
			p.otel.RecordGuardrailEvaluation(ctx, "cisco-ai-defense", verdict.Action)
		}
		if tokIn != nil || tokOut != nil {
			p.otel.RecordLLMTokens(ctx, "apply_guardrail", "defenseclaw", model, p.connectorName(), p.agentIDForRequest(), ptrOr(tokIn, 0), ptrOr(tokOut, 0))
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
	// bytes.TrimSpace keeps this helper safe against pretty-printed
	// RawMessage values that may carry incidental leading whitespace
	// before the array bracket.
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return ""
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(trimmed, &parts); err != nil {
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
			// bytes.TrimSpace tolerates pretty-printed bodies (e.g. jq-piped
			// replays or LiteLLM debug mode) where the RawMessage payload
			// has incidental leading whitespace — without it, a string
			// content with leading space would fall through and never be
			// probed for the banner, leaking into upstream.
			contentTrim := bytes.TrimSpace(probe.Content)
			if len(contentTrim) > 0 {
				var text string
				switch contentTrim[0] {
				case '"':
					_ = json.Unmarshal(contentTrim, &text)
				case '[':
					text = responsesTextFromContent(contentTrim)
				}
				if strings.HasPrefix(text, defenseClawBlockBanner) {
					stripped++
					continue
				}
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
	// bytes.TrimSpace tolerates pretty-printed bodies — a whitespace-
	// prefixed JSON array would otherwise be misclassified as a plain
	// string `input` and the body returned unchanged, leaking the
	// banner'd item into upstream.
	inputTrim := bytes.TrimSpace(inputBytes)
	if !ok || len(inputTrim) == 0 || inputTrim[0] != '[' {
		return raw, 0, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(inputTrim, &items); err != nil {
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
// launderer via the FormatAdapter registry. Returns the (possibly
// mutated) body and the count of stripped turns. Errors are logged at
// the call site but never fail the request — a laundering failure
// should never block a legitimate user.
//
// When no adapter claims the path the body is returned unchanged with
// a 0 strip count. That is the correct no-op for formats we don't yet
// understand (better than false positives on unrelated payloads).
func launderInboundHistory(raw json.RawMessage, path string) (json.RawMessage, int) {
	a := adapterFor(path, "")
	if a == nil {
		return raw, 0
	}
	out, n, err := a.LaunderHistory(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] launder inbound history (%s): %v\n", a.Name(), err)
		return raw, 0
	}
	return out, n
}

// injectNotificationForPassthrough dispatches to the correct format-aware
// injector via the FormatAdapter registry. Returns the mutated raw body
// and a label describing the injection site (<adapter>/<slot>) for
// observability. When no adapter claims the path, returns the original
// bytes, the empty label, and a non-nil error so the caller can log-and-
// forward without mutating the body.
//
// Adapter coverage (see buildAdapterRegistry for the match order):
//   - openai-responses → merges into top-level `instructions` string
//   - openai-chat      → prepends role:"system" into messages[]
//     (also handles /messages Anthropic-shaped paths in Phase 1; Phase 2
//     replaces that with a proper Anthropic adapter that uses the
//     top-level `system` field instead)
func injectNotificationForPassthrough(raw json.RawMessage, content, path string) (json.RawMessage, string, error) {
	a := adapterFor(path, "")
	if a == nil {
		return raw, "", fmt.Errorf("proxy: inject passthrough: no adapter claims path %q", path)
	}
	out, err := a.InjectSystem(raw, content)
	if err != nil {
		return raw, "", err
	}
	return out, a.InjectionSite(), nil
}

// ---------------------------------------------------------------------------
// Tool call inspection (defense-in-depth)
//
// When the LLM responds with tool_calls, inspect each tool's name and
// arguments with the same ScanAllRules engine used by the inspect endpoint.
// This catches dangerous tool calls (write_file with /etc/passwd, shell with
// reverse shells, etc.) even when the agent's tool-inspection hook is not loaded.
//
// In "action" mode, tool-call chunks are buffered and only released after
// post-stream inspection passes. In "observe" mode, tool-call deltas are
// forwarded to the client as they arrive (by design) and the post-stream
// scan is purely alerting.
// ---------------------------------------------------------------------------

// inspectToolCalls scans tool call arguments in an OpenAI-format tool_calls
// JSON array. Returns a verdict when the configured guardrail policy produces
// an alert or block; unsupported HILT confirmations degrade to alert+audit.
func (p *GuardrailProxy) inspectToolCalls(ctx context.Context, toolCallsJSON json.RawMessage) *ScanVerdict {
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
			_ = p.logger.LogActionCtx(ctx, "guardrail-tool-call-parse-error", "", err.Error())
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

	action := guardrailRuntimeActionForGuardrail(p.cfg, severity, false)
	if action == guardrailActionAllow {
		return nil
	}
	if action == guardrailActionConfirm {
		action = guardrailActionAlert
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
			_ = p.logger.LogActionCtx(ctx, "guardrail-tool-call-inspect", tc.Function.Name,
				fmt.Sprintf("action=%s severity=%s confidence=%.2f", action, severity, confidence))
		}
	}

	if p.otel != nil {
		p.otel.RecordGuardrailEvaluation(ctx, p.connectorName()+":tool-call-inspect", action)
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
			llmCtx, name, "pending", json.RawMessage(tc.Function.Arguments), false, "", "", "",
			telemetry.ToolSpanContext{
				ToolID:         tc.ID,
				SessionID:      conversationID,
				DestinationApp: "builtin",
				PolicyID:       p.defaultPolicyID,
				AgentName:      agentName,
				AgentType:      agentName,
				AgentID:        p.agentIDForRequest(),
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

// rawForwardChatCompletion preserves the original OpenAI-compatible JSON body
// for fetch-intercepted requests while keeping DefenseClaw PRE-CALL and
// POST-CALL guardrail checks active.
func (p *GuardrailProxy) rawForwardChatCompletion(w http.ResponseWriter, r *http.Request, body []byte, req *ChatRequest) {
	targetOrigin := strings.TrimRight(req.TargetURL, "/")
	if targetOrigin == "" {
		writeOpenAIError(w, http.StatusBadRequest, "missing X-DC-Target-URL header")
		return
	}

	upstreamURL := targetOrigin + r.URL.RequestURI()

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	forwardBody := body
	if len(req.RawBody) > 0 {
		forwardBody = req.RawBody
	}

	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(forwardBody))
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "failed to create upstream request")
		return
	}

	upReq.Header.Set("Content-Type", "application/json")
	if req.TargetAPIKey != "" {
		upReq.Header.Set("Authorization", "Bearer "+strings.TrimPrefix(req.TargetAPIKey, "Bearer "))
	}
	if v := r.Header.Get("Accept"); v != "" {
		upReq.Header.Set("Accept", v)
	}

	resp, err := providerHTTPClient.Do(upReq)
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "upstream provider error: "+err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "failed to read upstream response")
		return
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		for k, vals := range resp.Header {
			if strings.EqualFold(k, "Content-Length") {
				continue
			}
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	completion, usage := extractRawForwardCompletion(respBody, req.Stream)

	if completion != "" {
		p.reloadRuntimeConfig()
		p.rtMu.RLock()
		mode := p.mode
		customBlockMsg := p.blockMessage
		p.rtMu.RUnlock()

		postCtx, postCancel := p.postCallContext(r.Context())
		defer postCancel()

		postStart := time.Now()
		respMessages := []ChatMessage{{Role: "assistant", Content: completion}}
		verdict := p.inspector.Inspect(postCtx, "completion", completion, respMessages, req.Model, mode)
		p.logPostCall(req.Model, completion, verdict, time.Since(postStart), usage)
		p.recordTelemetry(r.Context(), "completion", req.Model, verdict, time.Since(postStart), nil, nil)

		if verdict != nil && verdict.Action == "block" && mode == "action" {
			msg := blockMessage(customBlockMsg, "completion", verdict.Reason)
			p.enqueueBlockNotification(verdict, "completion", req.Model)
			if req.Stream {
				p.writeBlockedStream(w, req.Model, msg)
			} else {
				p.writeBlockedResponse(w, req.Model, msg)
			}
			return
		}
	}

	for k, vals := range resp.Header {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}

	if w.Header().Get("Content-Type") == "" {
		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
	}

	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// extractRawForwardCompletion extracts assistant-visible text only.
//
// For non-streaming responses, it reads choices[].message.content.
// For streaming responses, it reads choices[].delta.content.
// It deliberately does not scan the original request body, tool schemas,
// system prompts, or raw SSE JSON.
func extractRawForwardCompletion(respBody []byte, stream bool) (string, *ChatUsage) {
	if !stream {
		var parsed ChatResponse
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return "", nil
		}

		out := strings.Builder{}
		for _, ch := range parsed.Choices {
			if ch.Message != nil && ch.Message.Content != "" {
				out.WriteString(ch.Message.Content)
			}
		}
		return out.String(), parsed.Usage
	}

	out := strings.Builder{}

	lines := strings.Split(string(respBody), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}

		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}

		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				Message *ChatMessage `json:"message,omitempty"`
			} `json:"choices"`
		}

		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}

		for _, ch := range chunk.Choices {
			if ch.Delta.Content != "" {
				out.WriteString(ch.Delta.Content)
			}
			if ch.Message != nil && ch.Message.Content != "" {
				out.WriteString(ch.Message.Content)
			}
		}
	}

	return out.String(), nil
}
