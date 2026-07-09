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
	"time"
)

// RemoteRouterClient implements ModelRouter by calling the vLLM Semantic Router
// classify/intent API. It gets a routing decision (which model to use) without
// forwarding the request — DefenseClaw handles forwarding via Bifrost.
type RemoteRouterClient struct {
	endpoint string // e.g. "http://127.0.0.1:8080"
	timeout  time.Duration
	client   *http.Client
}

// NewRemoteRouterClient creates a client for the semantic router API server.
func NewRemoteRouterClient(endpoint string, timeoutMs int) *RemoteRouterClient {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	return &RemoteRouterClient{
		endpoint: endpoint,
		timeout:  timeout,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// classifyRequest is the JSON body sent to POST /api/v1/classify/intent.
type classifyRequest struct {
	Messages []classifyMessage  `json:"messages"`
	Text     string             `json:"text,omitempty"`
	Options  *classifyOptions   `json:"options,omitempty"`
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
	MatchedSignals   map[string]interface{} `json:"matched_signals"`
	DecisionResult   classifyDecisionResult `json:"decision_result"`
}

type classifyClassification struct {
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
}

type classifyDecisionResult struct {
	DecisionName string  `json:"decision_name"`
	Confidence   float64 `json:"confidence"`
}

func (c *RemoteRouterClient) Route(ctx context.Context, input *ModelRouterInput) *ModelRouterDecision {
	if c == nil || c.endpoint == "" {
		return nil
	}

	msgs := make([]classifyMessage, len(input.Messages))
	for i, m := range input.Messages {
		msgs[i] = classifyMessage{Role: m.Role, Content: m.Content}
	}

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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		fmt.Fprintf(os.Stderr, "[routing] sr error %d: %s\n", resp.StatusCode, body)
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

	reason := fmt.Sprintf("decision=%s model=%s confidence=%.2f",
		classResp.RoutingDecision, classResp.RecommendedModel, classResp.Classification.Confidence)

	fmt.Fprintf(os.Stderr, "[routing] route: %s\n", reason)

	return &ModelRouterDecision{
		Model:  classResp.RecommendedModel,
		Reason: reason,
	}
}

// Healthy checks if the SR service is reachable.
func (c *RemoteRouterClient) Healthy(ctx context.Context) bool {
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, c.endpoint+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
