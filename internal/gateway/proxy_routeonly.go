// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// Route-only mode (DESIGN 7, 15, 16, 17, 18): hook connectors (Claude Code,
// Codex) point their model base URL at /r/<connector>/ on the gateway API
// listener. The gateway runs only the router and forwards with streaming
// intact; it does not scan the request (the hooks decide every tool call).

const (
	routeOnlyBodyCap       = 64 << 20
	routeOnlyRetryBodyCap  = 8 << 20
	routeOnlyPerSubjectMax = 32
	routeOnlyRetryWindow   = 10 * time.Second
	// routeOnlyBufferBudget bounds the request bodies buffered at once (for
	// routing and retry); over it a request streams unrouted.
	routeOnlyBufferBudget = 256 << 20
)

// routeOnlyServer serves /r/<connector>/... requests.
type routeOnlyServer struct {
	router   *engineRouter
	config   func() *config.Config
	tokens   *routeTokenStore
	client   *http.Client
	ownerUID int
	// api answers verified callers on a managed gateway (set by
	// APIServer.SetRouteOnly); goos selects the credential custody rule.
	api  *APIServer
	goos string

	mu        sync.Mutex
	inflight  map[string]int
	heldBytes int64
	signers   bedrockSigners
}

func newRouteOnlyServer(router *engineRouter, cfg func() *config.Config, dataDir string) *routeOnlyServer {
	transport := &http.Transport{
		DialContext:           enterpriseEgressDialer{direct: &net.Dialer{Timeout: 10 * time.Second}}.DialContext,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
	}
	return &routeOnlyServer{
		router: router, config: cfg, tokens: newRouteTokenStore(dataDir, routeOwner()),
		ownerUID: os.Getuid(), inflight: map[string]int{}, goos: runtime.GOOS,
		client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

// routeOnlyDispatch claims /r/ requests before the API middleware chain
// (Correlation, token auth, CSRF, body limit), so none of them sees or
// skips a route-only request (DESIGN 16.1).
func routeOnlyDispatch(ro func() *routeOnlyServer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !routeOnlyClaim(r) {
			next.ServeHTTP(w, r)
			return
		}
		s := ro()
		if s == nil {
			http.NotFound(w, r)
			return
		}
		s.ServeHTTP(w, r)
	})
}

func routeOnlyError(w http.ResponseWriter, status int, kind, msg string) {
	routeOnlyErrorFor(w, "", status, kind, msg)
}

// routeOnlyErrorFor writes the error in the shape the agent API uses
// (S11 F6: provider-native refusal bodies): Anthropic Messages, OpenAI
// chat/Responses, Bedrock.
func routeOnlyErrorFor(w http.ResponseWriter, family string, status int, kind, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	msg = "[DefenseClaw] " + msg
	var body []byte
	switch family {
	case config.RoutingAPIChat, config.RoutingAPIResponses:
		body, _ = json.Marshal(map[string]any{"error": map[string]any{"message": msg, "type": kind, "code": kind}})
	case config.RoutingAPIConverse, config.RoutingAPIInvoke:
		w.Header().Set("X-Amzn-ErrorType", "AccessDeniedException")
		body, _ = json.Marshal(map[string]any{"message": msg})
	default:
		body, _ = json.Marshal(map[string]any{"type": "error", "error": map[string]string{"type": kind, "message": msg}})
	}
	_, _ = w.Write(body)
}

func isLoopbackRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackHostHeader(h string) bool {
	host := h
	if hh, _, err := net.SplitHostPort(h); err == nil {
		host = hh
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ServeHTTP implements the route-only chain.
func (s *routeOnlyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	connector, native, ok := routeOnlyParse(r)
	if !ok {
		routeOnlyError(w, http.StatusBadRequest, "invalid_request_error", "malformed route-only path")
		return
	}
	cfg := s.config()
	if cfg == nil || !cfg.Routing.Enabled || !slices.Contains(cfg.Routing.RouteOnly.Connectors, connector) {
		http.NotFound(w, r)
		return
	}
	if !isLoopbackRemote(r.RemoteAddr) {
		routeOnlyError(w, http.StatusForbidden, "permission_error", "route-only answers loopback callers only")
		return
	}
	if r.Header.Get("Origin") != "" || r.Method == http.MethodOptions || !isLoopbackHostHeader(r.Host) {
		routeOnlyError(w, http.StatusForbidden, "permission_error", "browser and non-loopback requests are refused")
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		// Codex falls back to HTTP; a tunnel would skip routing and usage.
		routeOnlyError(w, http.StatusUpgradeRequired, "invalid_request_error", "route-only does not upgrade connections; use HTTP")
		return
	}
	isModels := strings.HasSuffix(strings.TrimRight(native, "/"), "/models") || strings.Contains(native, "/models/")
	if r.Method != http.MethodPost && !((r.Method == http.MethodGet || r.Method == http.MethodHead) && isModels) {
		routeOnlyError(w, http.StatusMethodNotAllowed, "invalid_request_error", "route-only accepts POST, and GET on the models path")
		return
	}
	caller := s.caller(r, cfg, connector)
	if !caller.Verified {
		// Never the credential or a header value: the connector and why.
		fmt.Fprintf(os.Stderr, "[routing] route-only refused connector=%s reason=%s\n", connector, caller.Reason)
		if caller.Reason == routeCallerPeerLookupLimited {
			// A burst of new connections over the account own lookup bound:
			// agents retry a 429.
			w.Header().Set("Retry-After", "1")
			routeOnlyError(w, http.StatusTooManyRequests, "rate_limit_error", routeCallerRefusalText(caller.Reason))
			return
		}
		routeOnlyError(w, http.StatusUnauthorized, "authentication_error", routeCallerRefusalText(caller.Reason))
		return
	}
	upstream, ok := cfg.Routing.RouteOnly.Upstreams[connector]
	if !ok || strings.TrimSpace(upstream.BaseURL) == "" {
		routeOnlyError(w, http.StatusServiceUnavailable, "api_error", "routing.route_only.upstreams."+connector+" is not set; run the routing enable step again")
		return
	}
	// Gateway signing (DESIGN 7.3, 15.6): the agent sends no AWS credential
	// and every upstream attempt is signed here.
	var signer *bedrockSigner
	if bedrockGatewaySigning(upstream.Bedrock) {
		// Only the four model calls the routing gate judges are signed with
		// the gateway identity; anything else is refused before signing.
		if !bedrockSignableRequest(r.Method, native) {
			routeOnlyError(w, http.StatusForbidden, "permission_error", "DefenseClaw signs only Bedrock Converse and InvokeModel calls (POST /model/{id}/converse, converse-stream, invoke or invoke-with-response-stream)")
			return
		}
		if strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "AWS4-HMAC-SHA256") {
			routeOnlyError(w, http.StatusBadRequest, "invalid_request_error", "the agent signed this Bedrock request itself (for the loopback host); set CLAUDE_CODE_SKIP_BEDROCK_AUTH=1 by running the routing enable step again")
			return
		}
		sg, err := s.signers.get(cfg, upstream.Bedrock, upstream.BaseURL)
		if err != nil {
			bedrockSignLogf("setup:"+connector, "[routing] route-only %s: gateway Bedrock signing unavailable: %v\n", connector, err)
			routeOnlyError(w, http.StatusServiceUnavailable, "api_error", "gateway Bedrock signing is not ready for routing.route_only.upstreams."+connector+".bedrock; run defenseclaw doctor")
			return
		}
		signer = sg
	}
	// Managed Windows and macOS: no agent provider credential is forwarded
	// (DESIGN 16.2: another account can hold the port while the gateway
	// restarts there); the gateway uses its own credential for the target.
	custody := s.custody(cfg)
	subject := caller.Subject
	if cfg.StandaloneEnterprise() {
		// Managed: the proved account is the subject downstream (profile
		// matching, audit). OSS: the gateway owner, as before.
		r = r.WithContext(attachVerifiedSubject(r.Context(), nil, subject, sanitizeLLMEventUser(userScopedIdentityName(subject)), subjectSourceKernelPeer))
	}
	if !s.acquire(subject) {
		routeOnlyError(w, http.StatusTooManyRequests, "rate_limit_error", "too many concurrent model calls through DefenseClaw")
		return
	}
	defer s.release(subject)

	original := routeOnlyAttempt{base: upstream.BaseURL, native: native, keepInbound: true, signer: signer}
	if custody {
		if !s.holdCredential(cfg, &original, routeOnlyProvider(routeOnlyAPIFamily(native))) {
			routeOnlyError(w, http.StatusServiceUnavailable, "api_error", "route-only on this managed host forwards no agent credential: set routing.models[].credential for the upstream of "+connector)
			return
		}
	}
	if r.Method != http.MethodPost {
		s.forward(w, r, original, nil, nil)
		return
	}
	// Bodies are buffered under one global budget; a request that does not
	// fit streams to the configured upstream unrouted (never refused).
	// A signed call cannot stream unhashed: when the budget is full it is
	// answered overloaded (the agent retries); 413 stays for the 64 MiB cap.
	if r.ContentLength > routeOnlyBodyCap || !s.holdBody(max(r.ContentLength, 0)) {
		if signer != nil && r.ContentLength <= routeOnlyBodyCap {
			routeOnlyOverloaded(w)
			return
		}
		s.forward(w, r, original, nil, r.Body)
		return
	}
	charged := max(r.ContentLength, 0)
	defer func() { s.releaseBody(charged) }()
	body, over, err := readRouteOnlyBody(r)
	if err != nil {
		routeOnlyError(w, http.StatusBadRequest, "invalid_request_error", "could not read the request body")
		return
	}
	if extra := int64(len(body)) - charged; extra > 0 {
		if !s.holdBody(extra) {
			if signer != nil && over == nil {
				routeOnlyOverloaded(w)
				return
			}
			s.forward(w, r, original, body, over)
			return
		}
		charged += extra
	}
	if over != nil {
		s.forward(w, r, original, body, over)
		return
	}
	family := routeOnlyAPIFamily(native)
	inClass := routeOnlyCredentialClass(r.Header, family)
	if signer != nil {
		inClass = engine.CredentialGateway
	}
	if inClass == "sigv4" {
		routeOnlyError(w, http.StatusBadRequest, "invalid_request_error", "a SigV4-signed Bedrock request cannot pass through the gateway; use a Bedrock API key, or gateway signing (bedrock.auth profile, instance_role or iam_credentials)")
		return
	}
	if custody {
		// The agent sent the placeholder (or a credential that is dropped):
		// every attempt uses a gateway-held credential.
		inClass = engine.CredentialGateway
	}
	original.usage = routeOnlyUsageFacts(connector, native, family, body)
	// The verified caller (OSS gateway owner or managed kernel peer).
	original.usage.Subject = subject
	attempt, routedOutcome, originalAllowed := s.decide(r, cfg, connector, native, family, upstream, inClass, signer, body, engine.Caller{Verified: true, Key: subject, Source: subjectSourceKernelPeer})
	original.usage.Route = usageDecision(usageRouteFacts(routedOutcome, true), false)
	if routedOutcome.Result == "" {
		original.usage.Route.Decision = modelusage.DecisionPassthrough
	}
	if routedOutcome.Route != nil {
		// Unrouted calls are charged too (S11 budgets).
		original.usage.ChargeKeys = routedOutcome.Route.ChargeKeys
	}
	if attempt != nil {
		attempt.usage = original.usage
		attempt.usage.Route = usageRouteFacts(routedOutcome, true)
		attempt.usage.SelectedProvider = attempt.provider
		if routedOutcome.Decision != nil {
			attempt.usage.SelectedModel = routedOutcome.Decision.Model
		}
		if routedOutcome.Route != nil {
			attempt.usage.ChargeKeys = routedOutcome.Route.ChargeKeys
		}
		// The retry of the original is a fallback record (DESIGN 17.3).
		original.usage.Route.Decision = modelusage.DecisionFallback
	}
	if routedOutcome.Result == SemanticRouteDenied {
		routeOnlyErrorFor(w, family, http.StatusForbidden, "permission_error", strings.TrimPrefix(routeDenyMessage(routedOutcome), "[DefenseClaw] "))
		return
	}
	if attempt != nil && custody && attempt.keepInbound && !s.holdCredential(cfg, attempt, attempt.provider) {
		attempt = nil
	}
	if attempt == nil {
		s.forward(w, r, original, body, nil)
		return
	}
	var retry *routeOnlyAttempt
	if originalAllowed && len(body) <= routeOnlyRetryBodyCap {
		retry = &original
	}
	w.Header().Set("X-Semantic-Router", "routed")
	s.forwardWithRetry(w, r, *attempt, retry, body)
}

// routeOnlyOverloaded answers a signed call the buffer budget cannot hold.
func routeOnlyOverloaded(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	routeOnlyError(w, http.StatusServiceUnavailable, "overloaded_error", "DefenseClaw is holding too many request bodies to sign; retry shortly")
}

func (s *routeOnlyServer) acquire(subject string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[subject] >= routeOnlyPerSubjectMax {
		return false
	}
	s.inflight[subject]++
	return true
}

func (s *routeOnlyServer) release(subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[subject]--; s.inflight[subject] <= 0 {
		delete(s.inflight, subject)
	}
}

func (s *routeOnlyServer) holdBody(n int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.heldBytes+n > routeOnlyBufferBudget {
		return false
	}
	s.heldBytes += n
	return true
}

func (s *routeOnlyServer) releaseBody(n int64) {
	s.mu.Lock()
	s.heldBytes -= n
	s.mu.Unlock()
}

// readRouteOnlyBody reads up to routeOnlyBodyCap; over is the unread rest
// when the body is larger (forwarded unrouted, never refused).
func readRouteOnlyBody(r *http.Request) ([]byte, io.Reader, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, routeOnlyBodyCap+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > routeOnlyBodyCap {
		return body, r.Body, nil
	}
	return body, nil, nil
}

// routeOnlyAttempt is one upstream call.
type routeOnlyAttempt struct {
	base        string // base URL: scheme://host[/prefix]
	native      string // escaped native path (+ query from the request)
	body        []byte // nil = the request body
	keepInbound bool   // forward the agent credential and headers
	auth        string // gateway-held credential (header form set by authHeader)
	provider    string
	signer      *bedrockSigner // gateway SigV4 signing (nil: none)
	usage       modelusage.CallFacts
}

// routeOnlyAPIFamily names the routable API family of a native path.
func routeOnlyAPIFamily(native string) string {
	if f := passthroughAPIFamily(native); f != "" {
		return f
	}
	p := strings.TrimRight(native, "/")
	switch {
	case p == "/responses":
		return config.RoutingAPIResponses
	case strings.HasSuffix(p, "/chat/completions"):
		return config.RoutingAPIChat
	}
	return ""
}

// routeOnlyProvider is the provider family an API family talks to.
func routeOnlyProvider(family string) string {
	switch family {
	case config.RoutingAPIMessages:
		return "anthropic"
	case config.RoutingAPIConverse, config.RoutingAPIInvoke:
		return "bedrock"
	default:
		return "openai"
	}
}

// routeOnlyCredentialClass classifies the inbound credential (DESIGN 7.3).
func routeOnlyCredentialClass(h http.Header, family string) string {
	auth := strings.TrimSpace(h.Get("Authorization"))
	switch {
	case strings.HasPrefix(auth, "AWS4-HMAC-SHA256"):
		return "sigv4"
	case family == config.RoutingAPIConverse || family == config.RoutingAPIInvoke:
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			return engine.CredentialBearer
		}
		return engine.CredentialNone
	case h.Get("X-Api-Key") != "":
		return engine.CredentialAPIKey
	case strings.HasPrefix(auth, "Bearer sk-ant-oat"):
		return engine.CredentialOAuth
	case strings.HasPrefix(auth, "Bearer sk-"):
		return engine.CredentialAPIKey
	case strings.HasPrefix(strings.ToLower(auth), "bearer "):
		// ChatGPT login tokens and other bearer forms are logins, not keys.
		return engine.CredentialOAuth
	}
	return engine.CredentialNone
}

const routeOnlyTextCap = 64 << 10

// routeOnlyHumanText returns the newest text the user typed (never tool
// output, system reminders or developer items) and request facts.
func routeOnlyHumanText(family string, body []byte) (text string, hasTools, toolTurn, images bool) {
	var probe struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Input json.RawMessage `json:"input"`
		Tools json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return "", false, false, false
	}
	hasTools = len(bytes.TrimSpace(probe.Tools)) > 2
	if family == config.RoutingAPIResponses {
		var s string
		if json.Unmarshal(probe.Input, &s) == nil {
			return capText(stripReminders(s)), hasTools, false, false
		}
		var items []struct {
			Type    string          `json:"type"`
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		_ = json.Unmarshal(probe.Input, &items)
		for i := len(items) - 1; i >= 0; i-- {
			it := items[i]
			if i == len(items)-1 && strings.HasSuffix(it.Type, "_output") {
				toolTurn = true
			}
			if it.Role == "user" && (it.Type == "" || it.Type == "message") {
				t, img := contentText(it.Content)
				images = images || img
				if t = capText(stripReminders(t)); t != "" {
					return t, hasTools, toolTurn, images
				}
			}
		}
		return "", hasTools, toolTurn, images
	}
	for i := len(probe.Messages) - 1; i >= 0; i-- {
		m := probe.Messages[i]
		if i == len(probe.Messages)-1 && (m.Role == "tool" || bytes.Contains(m.Content, []byte("\"tool_result\""))) {
			toolTurn = true
		}
		if m.Role != "user" {
			continue
		}
		t, img := contentText(m.Content)
		images = images || img
		if t = capText(stripReminders(t)); t != "" {
			return t, hasTools, toolTurn, images
		}
	}
	return "", hasTools, toolTurn, images
}

// contentText joins the text blocks of a content field (string or block
// list); tool_result blocks are skipped.
func contentText(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, false
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	_ = json.Unmarshal(raw, &blocks)
	var parts []string
	images := false
	for _, b := range blocks {
		switch b.Type {
		case "text", "input_text":
			parts = append(parts, b.Text)
		case "image", "input_image", "image_url":
			images = true
		case "":
			if b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
	}
	return strings.Join(parts, "\n"), images
}

// stripReminders removes <system-reminder> blocks in one pass. The input
// is bounded first (four times the classifier cap), so a large paste costs
// linear time on a bounded string.
func stripReminders(in string) string {
	in = truncateUTF8(in, 4*routeOnlyTextCap)
	const open, closeTag = "<system-reminder>", "</system-reminder>"
	var b strings.Builder
	for {
		i := strings.Index(in, open)
		if i < 0 {
			b.WriteString(in)
			break
		}
		b.WriteString(in[:i])
		j := strings.Index(in[i:], closeTag)
		if j < 0 {
			break
		}
		in = in[i+j+len(closeTag):]
	}
	return strings.TrimSpace(b.String())
}

func capText(s string) string { return truncateUTF8(s, routeOnlyTextCap) }

// conversationID is the agent session header, scoped to the caller by the
// engine sticky key.
func routeOnlyConversationID(h http.Header) string {
	for _, k := range []string{"X-Claude-Code-Session-Id", "Session_id", "Session-Id", "Conversation_id"} {
		if v := strings.TrimSpace(h.Get(k)); v != "" {
			return truncateUTF8(v, 128)
		}
	}
	return ""
}

// decide asks the router and returns the routed attempt (nil: send the
// original), the outcome, and whether the admin gate allows the original
// request as a fallback target.
func (s *routeOnlyServer) decide(r *http.Request, cfg *config.Config, connector, native, family string, upstream config.RoutingUpstreamConfig, inClass string, signer *bedrockSigner, body []byte, caller engine.Caller) (*routeOnlyAttempt, SemanticRouteOutcome, bool) {
	if s.router == nil {
		return nil, SemanticRouteOutcome{}, true
	}
	noRoute := false
	if family == "" && strings.HasSuffix(strings.TrimRight(native, "/"), "/responses/compact") {
		// Compact is forwarded unchanged but still passes the admin gate.
		family, noRoute = config.RoutingAPIResponses, true
	}
	if family == "" {
		return nil, SemanticRouteOutcome{}, true
	}
	text, hasTools, toolTurn, images := routeOnlyHumanText(family, body)
	var probe struct {
		Model    string `json:"model"`
		Previous string `json:"previous_response_id"`
	}
	_ = json.Unmarshal(body, &probe)
	model := probe.Model
	if family == config.RoutingAPIConverse || family == config.RoutingAPIInvoke {
		model = bedrockModelFromPath(native)
	}
	inProvider := routeOnlyProvider(family)
	in := &ModelRouterInput{
		Model: model, RequestModel: model, APIFamily: family, Connector: connector,
		Listener: engine.ListenerRouteOnly, RequestedProvider: inProvider, CredentialClass: inClass,
		ConversationID: routeOnlyConversationID(r.Header), Text: text, HasImages: images, ToolTurn: toolTurn,
		Caller: caller,
	}
	if hasTools {
		in.Tools = []interface{}{true}
	}
	out := s.router.RouteDetailed(r.Context(), in)
	originalTarget := engine.GateTarget{Provider: inProvider, Model: model}
	originalAllowed := s.router.Gate(r.Context(), out, originalTarget) == nil
	if noRoute || out.Result != SemanticRouteApplied {
		if out.Result != SemanticRouteDenied && !originalAllowed {
			deny := s.router.Gate(r.Context(), out, originalTarget)
			out.Result, out.Deny, out.Decision = SemanticRouteDenied, deny, nil
		}
		return nil, out, originalAllowed
	}
	if out.Route != nil && out.Route.Backend != nil {
		b := out.Route.Backend
		if deny := s.router.Gate(r.Context(), out, engine.GateTarget{Alias: b.Alias, Provider: b.Provider, Model: b.Model}); deny != nil {
			out.Result, out.Deny, out.Decision = SemanticRouteDenied, deny, nil
			return nil, out, false
		}
	}
	d := out.Decision
	fallback := func() (*routeOnlyAttempt, SemanticRouteOutcome, bool) {
		if !originalAllowed {
			out.Result, out.Deny, out.Decision = SemanticRouteDenied, s.router.Gate(r.Context(), out, originalTarget), nil
		}
		return nil, out, originalAllowed
	}
	sameProvider := strings.EqualFold(d.Provider, inProvider)
	if !sameProvider && (inClass == engine.CredentialOAuth || inClass == engine.CredentialBearer) && d.APIKey == "" {
		// A login token or Bedrock bearer never crosses providers.
		return fallback()
	}
	if probe.Previous != "" && !sameProvider {
		return fallback()
	}
	origin := originOf(d.TargetURL)
	base := strings.TrimRight(strings.TrimSpace(d.TargetURL), "/")
	if origin == "" {
		if sameProvider {
			base, origin = strings.TrimRight(upstream.BaseURL, "/"), originOf(upstream.BaseURL)
		} else if o := providerDefaultOrigins[strings.ToLower(d.Provider)]; o != "" {
			base, origin = o, o
		}
	}
	if origin == "" {
		return fallback()
	}
	a := &routeOnlyAttempt{base: base, native: native, provider: firstNonEmptyRouteReason(d.Provider, inProvider)}
	switch family {
	case config.RoutingAPIConverse, config.RoutingAPIInvoke:
		if !strings.EqualFold(d.Provider, "bedrock") {
			return fallback()
		}
		u := &url.URL{Path: mustUnescape(native), RawPath: native}
		a.native = swapBedrockPathModel(u, d.Model)
		if a.native == "" {
			return fallback()
		}
	default:
		a.body = patchModelInBody(body, d.Model)
	}
	if d.APIKey == "" && sameProvider && strings.EqualFold(origin, originOf(upstream.BaseURL)) {
		a.keepInbound, a.signer = true, signer
	} else {
		if inClass == engine.CredentialOAuth && d.APIKey == "" {
			return fallback()
		}
		if inClass == engine.CredentialGateway && d.APIKey == "" {
			// Another Bedrock origin (region or endpoint): the gateway signs
			// for it with the alias block when that one signs, else with the
			// upstream credentials for the target host region.
			if !strings.EqualFold(d.Provider, "bedrock") {
				return fallback()
			}
			block := upstream.Bedrock
			if out.Route != nil && out.Route.Backend != nil && bedrockGatewaySigning(out.Route.Backend.Bedrock) {
				block = out.Route.Backend.Bedrock
			} else if bedrockRegionFromURL(base) != "" {
				cp := *block
				cp.Region = ""
				block = &cp
			}
			sg, err := s.signers.get(cfg, block, base)
			if err != nil {
				return fallback()
			}
			a.signer = sg
		}
		a.auth = d.APIKey
	}
	return a, out, originalAllowed
}

func mustUnescape(p string) string {
	if u, err := url.PathUnescape(p); err == nil {
		return u
	}
	return p
}

// hop-by-hop and DefenseClaw-internal headers never forwarded.
var routeOnlyDropHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	"Host", "Content-Length", "X-Ai-Auth", "Origin", "Cookie",
}

// headers allowed across a credential boundary (a routed backend that is
// not the agent own provider and origin).
var routeOnlyBoundaryHeaders = []string{"Content-Type", "Accept", "Accept-Encoding", "User-Agent", "Anthropic-Version", "Anthropic-Beta", "Openai-Beta"}

func connectionNamed(h http.Header) map[string]bool {
	out := map[string]bool{}
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if n := strings.TrimSpace(name); n != "" {
				out[http.CanonicalHeaderKey(n)] = true
			}
		}
	}
	return out
}

func routeOnlyForwardHeaders(dst, src http.Header, a routeOnlyAttempt) {
	named := connectionNamed(src)
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if named[ck] {
			continue
		}
		if slices.Contains(routeOnlyDropHeaders, ck) || strings.HasPrefix(ck, "X-Dc-") || strings.HasPrefix(ck, "X-Defenseclaw-") || strings.HasPrefix(ck, "X-User-") {
			continue
		}
		if !a.keepInbound && !slices.Contains(routeOnlyBoundaryHeaders, ck) {
			continue
		}
		dst[ck] = slices.Clone(vs)
	}
	if !a.keepInbound && a.auth != "" {
		switch strings.ToLower(a.provider) {
		case "anthropic":
			dst.Set("X-Api-Key", a.auth)
		default:
			dst.Set("Authorization", "Bearer "+a.auth)
		}
	}
}

func (a routeOnlyAttempt) url(query string) string {
	out := strings.TrimRight(a.base, "/") + a.native
	if query != "" && !strings.Contains(a.native, "?") {
		out += "?" + query
	}
	return out
}

func retryableRouteStatus(status int, crossProvider bool) bool {
	switch status {
	case http.StatusNotFound, http.StatusServiceUnavailable, 529:
		return true
	case http.StatusTooManyRequests:
		return crossProvider
	}
	return false
}

// forwardWithRetry sends the routed attempt and, when it fails before any
// response byte within the retry window, the original request once
// (DESIGN 16.5, 17.3). A transport error is retried only when the request
// was never written, so a backend that read the request is never billed
// twice; 500, 502 and 504 are never retried.
func (s *routeOnlyServer) forwardWithRetry(w http.ResponseWriter, r *http.Request, routed routeOnlyAttempt, original *routeOnlyAttempt, body []byte) {
	started := time.Now()
	routed.usage.RequestID = RequestIDFromContext(r.Context())
	call := usageRecorder().Begin(r.Context(), routed.usage)
	resp, wrote, err := s.send(r, routed, body, nil)
	if resp != nil {
		call.UpstreamHeader(resp.StatusCode, resp.Header)
	}
	cross := !strings.EqualFold(routed.provider, routeOnlyProvider(routeOnlyAPIFamily(routed.native)))
	retryable := (err != nil && !wrote) || (err == nil && retryableRouteStatus(resp.StatusCode, cross))
	if original != nil && retryable && r.Context().Err() == nil && time.Since(started) < routeOnlyRetryWindow {
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
		}
		call.End(errRouteOnlyRetried)
		fmt.Fprintf(os.Stderr, "[routing] route-only: routed call failed before its first byte; sending the original request\n")
		w.Header().Set("X-Semantic-Router", "fallback")
		s.forward(w, r, *original, body, nil)
		return
	}
	if err != nil {
		call.End(err)
		routeOnlySendError(w, err, "the routed model is unreachable")
		return
	}
	call.End(copyRouteOnlyResponse(w, resp, call, routed.usage.Streaming))
}

func (s *routeOnlyServer) forward(w http.ResponseWriter, r *http.Request, a routeOnlyAttempt, body []byte, rest io.Reader) {
	var call modelusage.Call = modelusage.Noop.Begin(r.Context(), a.usage)
	if a.usage.Listener != "" {
		// Calls without facts (GET models, bodies streamed unbuffered) are
		// not model calls with usage the gateway can attribute.
		a.usage.RequestID = RequestIDFromContext(r.Context())
		call = usageRecorder().Begin(r.Context(), a.usage)
	}
	resp, _, err := s.send(r, a, body, rest)
	if err != nil {
		call.End(err)
		routeOnlySendError(w, err, "the model upstream is unreachable")
		return
	}
	call.UpstreamHeader(resp.StatusCode, resp.Header)
	call.End(copyRouteOnlyResponse(w, resp, call, a.usage.Streaming))
}

// routeOnlyBoundaryQuery are the query keys kept across a credential
// boundary (Anthropic beta flags); others stay with the agent provider.
var routeOnlyBoundaryQuery = []string{"beta", "api-version"}

func (s *routeOnlyServer) send(r *http.Request, a routeOnlyAttempt, body []byte, rest io.Reader) (*http.Response, bool, error) {
	payload := body
	if a.body != nil {
		payload = a.body
	}
	var reader io.Reader = bytes.NewReader(payload)
	length := int64(len(payload))
	if rest != nil {
		reader, length = io.MultiReader(bytes.NewReader(payload), rest), -1
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		reader, length = nil, 0
	}
	query := r.URL.RawQuery
	if !a.keepInbound && query != "" {
		kept := url.Values{}
		for k, v := range r.URL.Query() {
			if slices.Contains(routeOnlyBoundaryQuery, k) {
				kept[k] = v
			}
		}
		query = kept.Encode()
	}
	wrote := false
	ctx := httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
		WroteHeaders: func() { wrote = true },
	})
	req, err := http.NewRequestWithContext(ctx, r.Method, a.url(query), reader)
	if err != nil {
		return nil, false, err
	}
	req.ContentLength = length
	routeOnlyForwardHeaders(req.Header, r.Header, a)
	if a.signer != nil {
		// Signed after the model id swap and the body patch, over the exact
		// bytes and path sent; every attempt (and the retry) signs anew.
		if rest != nil {
			return nil, false, errBedrockSignTooLarge
		}
		if err := a.signer.sign(r.Context(), req, payload); err != nil {
			return nil, false, err
		}
	}
	resp, err := s.client.Do(req)
	return resp, wrote, err
}

// copyRouteOnlyResponse streams the upstream answer with a flush per read,
// feeding the usage call (chunks when streaming, the body otherwise).
func copyRouteOnlyResponse(w http.ResponseWriter, resp *http.Response, call modelusage.Call, streaming bool) error {
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		ck := http.CanonicalHeaderKey(k)
		if slices.Contains(routeOnlyDropHeaders, ck) && ck != "Cookie" {
			continue
		}
		w.Header()[ck] = slices.Clone(vs)
	}
	w.WriteHeader(resp.StatusCode)
	if !streaming && strings.Contains(resp.Header.Get("Content-Type"), "event-stream") {
		streaming = true
	}
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	var body []byte
	over := false
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if streaming {
				call.Chunk(buf[:n])
			} else if !over {
				if len(body)+n > usageBodyCap {
					over, body = true, nil
				} else {
					body = append(body, buf[:n]...)
				}
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if !streaming && len(body) > 0 {
				call.Body(body)
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

var errRouteOnlyRetried = errors.New("routed attempt retried on the original upstream")

// routeOnlyUsageFacts are the usage facts of a route-only request before
// routing (the original upstream).
func routeOnlyUsageFacts(connector, native, family string, body []byte) modelusage.CallFacts {
	var probe struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	_ = json.Unmarshal(body, &probe)
	model := probe.Model
	if family == config.RoutingAPIConverse || family == config.RoutingAPIInvoke {
		model = bedrockModelFromPath(native)
	}
	fam := usageAPIFamily(native)
	provider := routeOnlyProvider(family)
	return modelusage.CallFacts{
		Listener: engine.ListenerRouteOnly, Connector: connector, APIFamily: fam, CallRole: modelusage.RoleAgent,
		Streaming:         usageStreaming(native, body, probe.Stream),
		RequestedProvider: provider, RequestedModel: model, SelectedProvider: provider, SelectedModel: model,
		Subject: routeOwner(), SubjectKind: "route_credential", IdentityVerified: true,
	}
}

// routeOnlySetupFor is the route-only rendering of connector derived from
// config.yaml on an OSS per-user gateway, or nil when the connector is not
// routed (Setup then restores an earlier render). Managed hosts render per
// enrolled user through the guardian (ManagedRouteOnlySetup), never from
// the gateway or into a machine-wide file (DESIGN 17.7).
func routeOnlySetupFor(cfg *config.Config, connectorName, apiAddr string) *connector.RouteOnlySetup {
	if cfg == nil || cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() {
		return nil
	}
	// Only connectors whose hooks DefenseClaw installs: teardown and
	// uninstall restore exactly those (REVIEW-code-slice5b P1-2). Managed
	// hosts render protected ledger targets through the guardian instead.
	if !slices.Contains(cfg.ActiveConnectors(), connectorName) {
		return nil
	}
	route := routeOnlySetupBase(cfg, connectorName, apiAddr)
	if route == nil {
		return nil
	}
	token, err := newRouteTokenStore(cfg.DataDir, routeOwner()).Token(connectorName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[routing] route-only credential for %s unavailable: %v\n", connectorName, err)
		return nil
	}
	route.Token = token
	return route
}

// ManagedRouteOnlySetup is the route-only rendering of one enrolled user on
// a managed (standalone) host: the guardian calls it for protected targets
// only and renders the result into that user agent files (Claude Code user
// settings.json, Codex ~/.codex/config.toml), with token the user route
// credential (connector.ManagedRouteToken). nil when the connector is not
// routed on this host.
func ManagedRouteOnlySetup(cfg *config.Config, connectorName, apiAddr, token string) *connector.RouteOnlySetup {
	if cfg == nil || !cfg.StandaloneEnterprise() || strings.TrimSpace(token) == "" {
		return nil
	}
	route := routeOnlySetupBase(cfg, connectorName, apiAddr)
	if route == nil {
		return nil
	}
	route.Token = token
	// Custody hosts give the agent a placeholder credential: its own key
	// or login token never reaches the loopback port (DESIGN 16.2, S1
	// REVIEW-code-slice4 P1-2).
	route.Custody = routeOnlyCustodyOS(managedRouteOnlyGOOS)
	return route
}

// RouteOnlyRouted reports whether config.yaml routes connector route-only.
func RouteOnlyRouted(cfg *config.Config, connectorName string) bool {
	return cfg != nil && cfg.Routing.Enabled && slices.Contains(cfg.Routing.RouteOnly.Connectors, connectorName)
}

// routeOnlySetupBase is the rendering without its credential, or nil.
func routeOnlySetupBase(cfg *config.Config, connectorName, apiAddr string) *connector.RouteOnlySetup {
	if !RouteOnlyRouted(cfg, connectorName) || strings.TrimSpace(apiAddr) == "" {
		return nil
	}
	// The agent always talks to the loopback listener, whatever the bind
	// address (0.0.0.0 or an IPv6 form is not a usable client URL).
	if _, port, err := net.SplitHostPort(apiAddr); err == nil {
		apiAddr = net.JoinHostPort("127.0.0.1", port)
	}
	up, ok := cfg.Routing.RouteOnly.Upstreams[connectorName]
	if !ok {
		return nil
	}
	route := &connector.RouteOnlySetup{BaseURL: "http://" + apiAddr + routeOnlyPrefix + connectorName}
	if up.API == config.RoutingAPIConverse || up.API == config.RoutingAPIInvoke {
		route.Bedrock = true
		if bedrockGatewaySigning(up.Bedrock) {
			// The agent skips its own AWS auth only when the gateway can
			// sign now (one credential fetched); otherwise the agent stays
			// direct.
			if err := bedrockRenderReady(cfg, up.Bedrock, up.BaseURL); err != nil {
				fmt.Fprintf(os.Stderr, "[routing] route-only for %s not rendered: gateway Bedrock signing cannot start: %v\n", connectorName, err)
				return nil
			}
			route.GatewaySigning = true
		}
	}
	return route
}

// applyRouteOnlyRenders re-renders the route-only agent config of every
// connector whose rendering differs between two configs (connector added or
// removed, routing turned on or off, upstream or API address changed).
// Managed hosts are skipped: the guardian owns agent files there.
func (s *Sidecar) applyRouteOnlyRenders(oldCfg, newCfg *config.Config) {
	if s == nil || oldCfg == nil || newCfg == nil || managed.IsManagedEnterprise(newCfg.DeploymentMode) {
		return
	}
	names := map[string]bool{}
	for _, c := range append(slices.Clone(oldCfg.Routing.RouteOnly.Connectors), newCfg.Routing.RouteOnly.Connectors...) {
		names[c] = true
	}
	registry := connector.NewDefaultRegistry()
	for name := range names {
		before := routeOnlySetupFor(oldCfg, name, apiListenAddr(oldCfg))
		after := routeOnlySetupFor(newCfg, name, apiListenAddr(newCfg))
		if reflect.DeepEqual(before, after) {
			continue
		}
		conn, ok := registry.Get(name)
		if !ok {
			continue
		}
		rc, ok := conn.(connector.RouteOnlyConnector)
		if !ok {
			continue
		}
		if err := rc.ApplyRouteOnly(connector.SetupOpts{DataDir: newCfg.DataDir}, after); err != nil {
			fmt.Fprintf(os.Stderr, "[routing] route-only render for %s: %v\n", name, err)
			continue
		}
		state := "removed"
		if after != nil {
			state = "written"
		}
		fmt.Fprintf(os.Stderr, "[routing] route-only config for %s %s; restart the agent to pick it up\n", name, state)
	}
}
