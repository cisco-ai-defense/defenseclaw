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
	"net/url"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// handleRoutedChatCompletion serves /v1/chat/completions on the API port.
// It runs the semantic model router to select the backend, then forwards
// the request to the chosen upstream (e.g. Ollama). This endpoint works
// regardless of connector type, enabling testing and direct API usage of
// the routing layer.
func (a *APIServer) handleRoutedChatCompletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req struct {
		Model    string        `json:"model"`
		Messages []ChatMessage `json:"messages"`
		Stream   bool          `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	mr := loadGlobalModelRouter()
	if mr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "semantic router not configured (routing.enabled=false or absent)")
		return
	}

	input := &ModelRouterInput{
		Model:    req.Model,
		Messages: req.Messages,
		Stream:   req.Stream,
	}

	decision := mr.Route(r.Context(), input)
	if decision == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "no routing decision (fallback)")
		return
	}

	if decision.CacheHit && !req.Stream {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Semantic-Router", "cache-hit")
		w.Header().Set("X-Semantic-Router-Reason", decision.Reason)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(decision.CachedResponse)
		return
	}

	// Resolve the recommended model from configured routing.models entries.
	// decision.Model contains the routing name (e.g. "code"); we look up
	// the actual provider model name and base_url from config.
	if decision.Model == "" {
		writeJSONError(w, http.StatusBadGateway, "router decision has no model")
		return
	}

	var targetBase string
	var apiKey string
	var actualModel string
	if a.scannerCfg != nil && a.scannerCfg.Routing.Enabled {
		for _, m := range a.scannerCfg.Routing.Models {
			if m.Name == decision.Model {
				targetBase = m.BaseURL
				actualModel = m.Model
				if m.APIKeyEnv != "" {
					apiKey = os.Getenv(m.APIKeyEnv)
				}
				break
			}
		}
	}

	// Patch model in body with the actual provider model name.
	forwardBody := body
	if actualModel != "" {
		forwardBody = patchModelInBody(body, actualModel)
	} else if decision.Model != "" {
		forwardBody = patchModelInBody(body, decision.Model)
	}

	if targetBase == "" {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("model %q not found in routing.models", decision.Model))
		return
	}

	upstreamURL := targetBase + "/v1/chat/completions"

	// Validate upstream URL with netguard protection before dialing.
	u, err := url.Parse(upstreamURL)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid upstream URL")
		return
	}
	if u.User != nil {
		writeJSONError(w, http.StatusForbidden, "upstream URL must not contain userinfo")
		return
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		writeJSONError(w, http.StatusForbidden, "upstream URL scheme must be http or https")
		return
	}
	// Private-host check relaxed for local development (Ollama on localhost).
	// Production deployments use public upstream URLs or explicit allowlist.
	if isPrivateHost(u.Hostname()) && !connector.IsLoopback(r) {
		writeJSONError(w, http.StatusForbidden, "upstream URL resolves to private or unsafe address")
		return
	}

	fmt.Fprintf(os.Stderr, "[api] routed chat: decision=%q model=%q → %s\n",
		decision.Reason, decision.Model, upstreamURL)

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(forwardBody))
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "failed to build upstream request")
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		upReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	// Use a client that does not follow redirects.
	noRedirectClient := &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := noRedirectClient.Do(upReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[api] routed chat upstream error: %v\n", err)
		writeJSONError(w, http.StatusBadGateway, "upstream request failed")
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("X-Semantic-Router", "routed")
	w.Header().Set("X-Semantic-Router-Reason", decision.Reason)
	w.WriteHeader(resp.StatusCode)

	if req.Stream {
		// Streaming response: use io.Copy with ResponseController flushing.
		rc := http.NewResponseController(w)
		flushWriter := &flushingWriter{w: w, rc: rc}
		if _, err := io.Copy(flushWriter, resp.Body); err != nil {
			// Write error - connection may be closed. Stop processing.
			return
		}
	} else {
		// Non-streaming response: simple copy.
		_, _ = io.Copy(w, resp.Body)
	}
}

// flushingWriter wraps a ResponseWriter to flush after each Write.
type flushingWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (fw *flushingWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err != nil {
		return n, err
	}
	_ = fw.rc.Flush()
	return n, nil
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"error":{"message":%q}}`, msg)
}
