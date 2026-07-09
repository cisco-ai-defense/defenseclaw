// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
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

// RemoteRouterClient implements ModelRouter by calling the vLLM Semantic Router API.
type RemoteRouterClient struct {
	endpoint string // e.g. "http://127.0.0.1:8080"
	timeout  time.Duration
	client   *http.Client
}

// NewRemoteRouterClient creates a client for the semantic router service.
func NewRemoteRouterClient(endpoint string, timeoutMs int) *RemoteRouterClient {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 50 * time.Millisecond
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

// routeRequest is the JSON body sent to POST /v1/route.
type routeRequest struct {
	Messages []routeMessage `json:"messages"`
	Model    string         `json:"model,omitempty"`
	Stream   bool           `json:"stream,omitempty"`
}

type routeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// routeResponse is the JSON body returned by POST /v1/route.
type routeResponse struct {
	Backend    string  `json:"backend"`
	Model      string  `json:"model"`
	Provider   string  `json:"provider"`
	BaseURL    string  `json:"base_url"`
	APIKey     string  `json:"api_key,omitempty"`
	Algorithm  string  `json:"algorithm"`
	Decision   string  `json:"decision"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

func (c *RemoteRouterClient) Route(ctx context.Context, input *ModelRouterInput) *ModelRouterDecision {
	if c == nil || c.endpoint == "" {
		return nil
	}

	msgs := make([]routeMessage, len(input.Messages))
	for i, m := range input.Messages {
		msgs[i] = routeMessage{Role: m.Role, Content: m.Content}
	}

	reqBody := routeRequest{
		Messages: msgs,
		Model:    input.Model,
		Stream:   input.Stream,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[routing] marshal error: %v\n", err)
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.endpoint+"/v1/route", bytes.NewReader(bodyBytes))
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

	var routeResp routeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&routeResp); err != nil {
		fmt.Fprintf(os.Stderr, "[routing] decode error: %v\n", err)
		return nil
	}

	// Resolve API key from env if the SR returns an env var name
	apiKey := routeResp.APIKey
	if apiKey == "" && routeResp.Provider != "" {
		// The actual key resolution happens later via Bifrost/provider pool
	}

	reason := routeResp.Reason
	if reason == "" {
		reason = fmt.Sprintf("decision=%s backend=%s algorithm=%s", routeResp.Decision, routeResp.Backend, routeResp.Algorithm)
	}

	fmt.Fprintf(os.Stderr, "[routing] route: decision=%s → backend=%s model=%s/%s\n",
		routeResp.Decision, routeResp.Backend, routeResp.Provider, routeResp.Model)

	return &ModelRouterDecision{
		TargetURL: routeResp.BaseURL,
		Model:     routeResp.Model,
		APIKey:    apiKey,
		Reason:    reason,
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
