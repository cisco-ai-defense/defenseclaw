// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// LocalKeywordSignal is a named set of keywords used for local fallback routing.
type LocalKeywordSignal struct {
	Name     string
	Keywords []string
	Operator string // "OR" or "AND"
}

// LocalKeywordDecision maps a keyword signal to a model backend.
type LocalKeywordDecision struct {
	Name      string
	Priority  int
	Signal    string // signal name to match
	ModelRef  string // backend alias
}

// RemoteRouterClient implements ModelRouter by calling the vLLM Semantic Router
// classify/intent API. It gets a routing decision (which model to use) without
// forwarding the request — DefenseClaw handles forwarding via Bifrost.
type RemoteRouterClient struct {
	endpoint     string // e.g. "http://127.0.0.1:8080"
	timeout      time.Duration
	client       *http.Client
	healthClient *http.Client
	backends     map[string]ModelRouterBackend
	dotenv       string
	keywordSignals   []LocalKeywordSignal
	keywordDecisions []LocalKeywordDecision
}

const remoteRouterHealthTimeout = 2 * time.Second

// NewRemoteRouterClient creates a client for the semantic router API server.
func NewRemoteRouterClient(endpoint string, timeoutMs int) *RemoteRouterClient {
	return newRemoteRouterClient(endpoint, timeoutMs, nil, "")
}

// NewConfiguredRemoteRouterClient creates a classifier client that resolves
// returned model aliases to gateway-owned forwarding targets.
func NewConfiguredRemoteRouterClient(endpoint string, timeoutMs int, backends []ModelRouterBackend, dotenvPath string) *RemoteRouterClient {
	return newRemoteRouterClient(endpoint, timeoutMs, backends, dotenvPath)
}

func newRemoteRouterClient(endpoint string, timeoutMs int, backends []ModelRouterBackend, dotenvPath string) *RemoteRouterClient {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	backendByName := make(map[string]ModelRouterBackend, len(backends))
	for _, backend := range backends {
		name := strings.TrimSpace(backend.Name)
		if name == "" {
			continue
		}
		backend.Name = name
		if _, exists := backendByName[name]; !exists {
			backendByName[name] = backend
		}
	}
	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	checkRedirect := func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &RemoteRouterClient{
		endpoint: strings.TrimRight(endpoint, "/"),
		timeout:  timeout,
		backends: backendByName,
		dotenv:   dotenvPath,
		client: &http.Client{
			Timeout: timeout,
			// Routing endpoints are operator-configured trust boundaries. Do not
			// let an endpoint redirect prompts or user metadata to a different
			// origin without that origin appearing explicitly in config.yaml.
			CheckRedirect: checkRedirect,
			Transport:     transport,
		},
		// Health probes have an availability budget independent from the
		// latency-sensitive classification path. Keep the same transport and
		// redirect boundary while preventing a 50ms classifier timeout from
		// clamping the sidecar's two-second health probe.
		healthClient: &http.Client{
			Timeout:       remoteRouterHealthTimeout,
			CheckRedirect: checkRedirect,
			Transport:     transport,
		},
	}
}

// classifyRequest is the JSON body sent to POST /api/v1/classify/intent.
type classifyRequest struct {
	Messages []classifyMessage `json:"messages"`
	Text     string            `json:"text,omitempty"`
	Options  *classifyOptions  `json:"options,omitempty"`
}

type classifyMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type classifyOptions struct {
	ReturnProbabilities bool `json:"return_probabilities,omitempty"`
}

// classifyResponse is the JSON body returned by POST /api/v1/classify/intent.
type classifyResponse struct {
	RecommendedModel string                 `json:"recommended_model"`
	RoutingDecision  string                 `json:"routing_decision"`
	Classification   classifyClassification `json:"classification"`
}

type classifyClassification struct {
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
}

func (c *RemoteRouterClient) Route(ctx context.Context, input *ModelRouterInput) *ModelRouterDecision {
	return c.RouteDetailed(ctx, input).Decision
}

func (c *RemoteRouterClient) RouteDetailed(ctx context.Context, input *ModelRouterInput) (outcome SemanticRouteOutcome) {
	started := time.Now()
	outcome = SemanticRouteOutcome{
		Result:      SemanticRouteFallback,
		FailureCode: SemanticRouteFailureConfig,
	}
	if input != nil {
		outcome.RequestModel = strings.TrimSpace(input.RequestModel)
		if outcome.RequestModel == "" {
			outcome.RequestModel = strings.TrimSpace(input.Model)
		}
	}
	defer func() {
		outcome.Latency = time.Since(started)
		outcome = normalizeSemanticRouteOutcome(outcome)
	}()

	if c == nil || c.endpoint == "" || input == nil {
		return outcome
	}

	// Send only the last user message to the classifier to avoid matching
	// keywords in system prompts, tool definitions, and conversation history.
	var lastUserMsg classifyMessage
	for i := len(input.Messages) - 1; i >= 0; i-- {
		if strings.EqualFold(input.Messages[i].Role, "user") {
			lastUserMsg = classifyMessage{Role: input.Messages[i].Role, Content: input.Messages[i].Content}
			break
		}
	}
	if lastUserMsg.Content == "" {
		fmt.Fprintf(os.Stderr, "[routing] classify: no user message found in %d messages (roles:", len(input.Messages))
		for _, m := range input.Messages {
			fmt.Fprintf(os.Stderr, " %s", m.Role)
		}
		fmt.Fprintf(os.Stderr, ")\n")
		return outcome
	}
	contentPreview := lastUserMsg.Content
	if len(contentPreview) > 200 {
		contentPreview = contentPreview[:200]
	}
	fmt.Fprintf(os.Stderr, "[routing] classify: last user msg (%d chars): %q\n", len(lastUserMsg.Content), contentPreview)

	reqBody := classifyRequest{
		Messages: []classifyMessage{lastUserMsg},
		Options:  &classifyOptions{ReturnProbabilities: true},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[routing] marshal error: %v\n", err)
		outcome.FailureCode = SemanticRouteFailureConfig
		return outcome
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.endpoint+"/api/v1/classify/intent", bytes.NewReader(bodyBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[routing] request build error: %v\n", err)
		outcome.FailureCode = SemanticRouteFailureConfig
		return outcome
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[routing] sr unreachable: trying local keyword fallback (%v)\n", err)
		if localResult := c.tryLocalKeywordFallback(input); localResult != nil {
			return *localResult
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || reqCtx.Err() != nil {
			outcome.FailureCode = SemanticRouteFailureTimeout
		} else {
			outcome.FailureCode = SemanticRouteFailureConfig
		}
		return outcome
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		fmt.Fprintf(os.Stderr, "[routing] classifier returned HTTP %d; trying local keyword fallback\n", resp.StatusCode)
		if localResult := c.tryLocalKeywordFallback(input); localResult != nil {
			return *localResult
		}
		outcome.FailureCode = SemanticRouteFailureUpstreamStatus
		return outcome
	}

	var classResp classifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&classResp); err != nil {
		fmt.Fprintf(os.Stderr, "[routing] decode error: trying local keyword fallback (%v)\n", err)
		if localResult := c.tryLocalKeywordFallback(input); localResult != nil {
			return *localResult
		}
		outcome.FailureCode = SemanticRouteFailureDecode
		return outcome
	}

	if classResp.RecommendedModel == "" {
		if localResult := c.tryLocalKeywordFallback(input); localResult != nil {
			return *localResult
		}
		outcome.FailureCode = SemanticRouteFailureDecode
		return outcome
	}

	routerDecision := boundedRouterLabel(classResp.RoutingDecision, 64)
	recommendedAlias := boundedRouterLabel(classResp.RecommendedModel, 128)
	if recommendedAlias == "" {
		outcome.FailureCode = SemanticRouteFailureDecode
		return outcome
	}
	reason := fmt.Sprintf("decision=%s model=%s confidence=%.2f",
		routerDecision, recommendedAlias, classResp.Classification.Confidence)

	decision := &ModelRouterDecision{
		Model:  recommendedAlias,
		Reason: reason,
	}

	// The classifier returns a configured alias, not necessarily the provider
	// model ID. Resolve it locally so API keys never cross the classifier trust
	// boundary and transparent proxy routing can actually change providers.
	if len(c.backends) > 0 {
		backend, ok := c.backends[recommendedAlias]
		if !ok {
			fmt.Fprintf(os.Stderr, "[routing] unknown model alias %q: falling back to default provider\n", recommendedAlias)
			outcome.FailureCode = SemanticRouteFailureUnknownAlias
			return outcome
		}
		model := strings.TrimSpace(backend.Model)
		if model == "" {
			fmt.Fprintf(os.Stderr, "[routing] model alias %q has no provider model: falling back to default provider\n", recommendedAlias)
			outcome.FailureCode = SemanticRouteFailureConfig
			return outcome
		}
		provider := strings.TrimSpace(backend.Provider)
		if provider == "" {
			fmt.Fprintf(os.Stderr, "[routing] model alias %q has no provider: falling back to default provider\n", recommendedAlias)
			outcome.FailureCode = SemanticRouteFailureConfig
			return outcome
		}
		decision.Provider = provider
		decision.Model = model
		decision.TargetURL = strings.TrimRight(strings.TrimSpace(backend.BaseURL), "/")
		decision.HostHeader = strings.TrimSpace(backend.HostHeader)
		decision.TargetURLOverride = true
		switch backend.Auth {
		case "passthrough":
			// Forward the client's original Authorization header unchanged.
			decision.APIKeyOverride = false
		case "none":
			// Strip the Authorization header (keyless backend).
			decision.APIKeyOverride = true
			decision.APIKey = ""
		default: // "api_key" or legacy empty
			decision.APIKeyOverride = true
			if backend.APIKeyEnv != "" {
				if tokenResolver != nil {
					resolved, err := tokenResolver(ctx, provider)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[routing] managed credential resolution failed for provider %q: %v\n", provider, err)
						outcome.FailureCode = SemanticRouteFailureCredential
						return outcome
					}
					decision.APIKey = strings.TrimSpace(resolved)
				} else {
					decision.APIKey = ResolveAPIKey(backend.APIKeyEnv, c.dotenv)
				}
				if decision.APIKey == "" {
					fmt.Fprintf(os.Stderr, "[routing] credential %q for model alias %q is unavailable: falling back to default provider\n", backend.APIKeyEnv, recommendedAlias)
					outcome.FailureCode = SemanticRouteFailureCredential
					return outcome
				}
			}
		}
	}

	return outcomeFromDecision(input, decision, time.Since(started))
}

func boundedRouterLabel(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" || limit <= 0 {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len()+len(string(r)) > limit {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SetLocalKeywords configures the local keyword fallback so the gateway can
// route by keyword when the remote semantic router is unreachable.
func (c *RemoteRouterClient) SetLocalKeywords(signals []LocalKeywordSignal, decisions []LocalKeywordDecision) {
	c.keywordSignals = signals
	c.keywordDecisions = decisions
}

// localKeywordClassify performs gateway-local keyword matching as a fallback
// when the remote semantic router is unavailable. Returns the matched backend
// alias or "" if no decision matched.
func (c *RemoteRouterClient) localKeywordClassify(text string) string {
	if len(c.keywordSignals) == 0 || len(c.keywordDecisions) == 0 {
		return ""
	}
	lower := strings.ToLower(text)
	matched := make(map[string]bool, len(c.keywordSignals))
	for _, sig := range c.keywordSignals {
		for _, kw := range sig.Keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				matched[sig.Name] = true
				break
			}
		}
	}
	type candidate struct {
		priority int
		modelRef string
	}
	var best *candidate
	for _, dec := range c.keywordDecisions {
		if !matched[dec.Signal] {
			continue
		}
		if best == nil || dec.Priority > best.priority {
			best = &candidate{priority: dec.Priority, modelRef: dec.ModelRef}
		}
	}
	if best != nil {
		return best.modelRef
	}
	return ""
}

func (c *RemoteRouterClient) tryLocalKeywordFallback(input *ModelRouterInput) *SemanticRouteOutcome {
	if input == nil || len(c.keywordSignals) == 0 {
		return nil
	}
	// Only classify based on the last user message to avoid matching
	// keywords in system prompts, tool definitions, and conversation history.
	var text string
	for i := len(input.Messages) - 1; i >= 0; i-- {
		if strings.EqualFold(input.Messages[i].Role, "user") {
			text = input.Messages[i].Content
			break
		}
	}
	if text == "" {
		return nil
	}
	alias := c.localKeywordClassify(text)
	textPreview := text
	if len(textPreview) > 200 {
		textPreview = textPreview[:200]
	}
	fmt.Fprintf(os.Stderr, "[routing] local keyword classify: text=%q signals=%d decisions=%d result=%q\n", textPreview, len(c.keywordSignals), len(c.keywordDecisions), alias)
	if alias == "" {
		return nil
	}
	backend, ok := c.backends[alias]
	if !ok {
		return nil
	}
	model := strings.TrimSpace(backend.Model)
	provider := strings.TrimSpace(backend.Provider)
	if model == "" || provider == "" {
		return nil
	}
	decision := &ModelRouterDecision{
		Model:             model,
		Provider:          provider,
		TargetURL:         strings.TrimRight(strings.TrimSpace(backend.BaseURL), "/"),
		HostHeader:        strings.TrimSpace(backend.HostHeader),
		TargetURLOverride: true,
		Reason:            fmt.Sprintf("local-keyword-fallback model=%s", alias),
	}
	switch backend.Auth {
	case "passthrough":
		decision.APIKeyOverride = false
	case "none":
		decision.APIKeyOverride = true
		decision.APIKey = ""
	default: // "api_key" or legacy empty
		decision.APIKeyOverride = true
		if backend.APIKeyEnv != "" {
			decision.APIKey = ResolveAPIKey(backend.APIKeyEnv, c.dotenv)
			if decision.APIKey == "" {
				fmt.Fprintf(os.Stderr, "[routing] local fallback: credential %q for %q unavailable\n", backend.APIKeyEnv, alias)
				return nil
			}
		}
	}
	result := outcomeFromDecision(input, decision, 0)
	fmt.Fprintf(os.Stderr, "[routing] local keyword fallback matched: %s → %s/%s\n", alias, provider, model)
	return &result
}

var _ ModelRouter = (*RemoteRouterClient)(nil)

// Healthy checks if the SR service is reachable.
func (c *RemoteRouterClient) Healthy(ctx context.Context) bool {
	if c == nil || c.healthClient == nil {
		return false
	}
	reqCtx, cancel := context.WithTimeout(ctx, remoteRouterHealthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, c.endpoint+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := c.healthClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
