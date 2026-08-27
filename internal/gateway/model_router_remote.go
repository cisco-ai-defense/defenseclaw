// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

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
	if c == nil || c.endpoint == "" || input == nil {
		return nil
	}

	msgs := make([]classifyMessage, len(input.Messages))
	for i, m := range input.Messages {
		msgs[i] = classifyMessage{Role: m.Role, Content: m.Content}
	}

	// v0.3's IntentRequest accepts only text, messages, and options. Keep
	// gateway-only identity, headers, tools, and policy metadata out of this
	// trust boundary rather than relying on the classifier to ignore them.
	reqBody := classifyRequest{
		Messages: msgs,
		Options:  &classifyOptions{ReturnProbabilities: true},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[routing] marshal error: %v\n", err)
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.endpoint+"/api/v1/classify/intent", bytes.NewReader(bodyBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[routing] request build error: %v\n", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[routing] sr unreachable: falling back to default provider (%v)\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// A classifier may echo request content in its error body. Never copy
		// that body into persistent gateway.log; the HTTP status is sufficient
		// for bounded operational diagnosis.
		_, _ = io.Copy(io.Discard, resp.Body)
		fmt.Fprintf(os.Stderr, "[routing] classifier returned HTTP %d; falling back to default provider\n", resp.StatusCode)
		return nil
	}

	var classResp classifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&classResp); err != nil {
		fmt.Fprintf(os.Stderr, "[routing] decode error: %v\n", err)
		return nil
	}

	if classResp.RecommendedModel == "" {
		return nil
	}

	routerDecision := boundedRouterLabel(classResp.RoutingDecision, 64)
	recommendedAlias := boundedRouterLabel(classResp.RecommendedModel, 128)
	if recommendedAlias == "" {
		return nil
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
			return nil
		}
		model := strings.TrimSpace(backend.Model)
		if model == "" {
			fmt.Fprintf(os.Stderr, "[routing] model alias %q has no provider model: falling back to default provider\n", recommendedAlias)
			return nil
		}
		provider := strings.TrimSpace(backend.Provider)
		if provider == "" {
			fmt.Fprintf(os.Stderr, "[routing] model alias %q has no provider: falling back to default provider\n", recommendedAlias)
			return nil
		}
		decision.Provider = provider
		decision.Model = model
		decision.TargetURL = strings.TrimRight(strings.TrimSpace(backend.BaseURL), "/")
		decision.TargetURLOverride = true
		// A routing decision always establishes a new credential boundary. Even
		// when the selected backend is keyless, clear the connector's original
		// provider key rather than forwarding it to a different backend.
		decision.APIKeyOverride = true
		if backend.APIKeyEnv != "" {
			if tokenResolver != nil {
				resolved, err := tokenResolver(ctx, provider)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[routing] managed credential resolution failed for provider %q: %v\n", provider, err)
					return nil
				}
				decision.APIKey = strings.TrimSpace(resolved)
			} else {
				decision.APIKey = ResolveAPIKey(backend.APIKeyEnv, c.dotenv)
			}
			if decision.APIKey == "" {
				fmt.Fprintf(os.Stderr, "[routing] credential %q for model alias %q is unavailable: falling back to default provider\n", backend.APIKeyEnv, recommendedAlias)
				return nil
			}
		}
	}

	return decision
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
