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

	// Patch model in body if router overrides it.
	forwardBody := body
	if decision.Model != "" {
		forwardBody = patchModelInBody(body, decision.Model)
	}

	// Build upstream URL: base_url + /v1/chat/completions (Ollama OpenAI-compat).
	targetBase := decision.TargetURL
	if targetBase == "" {
		writeJSONError(w, http.StatusBadGateway, "router decision has no target URL")
		return
	}
	upstreamURL := targetBase + "/v1/chat/completions"

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
	if decision.APIKey != "" {
		upReq.Header.Set("Authorization", "Bearer "+decision.APIKey)
	}

	resp, err := http.DefaultClient.Do(upReq)
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
		flusher, _ := w.(http.Flusher)
		buf := make([]byte, 4096)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if rerr != nil {
				return
			}
		}
	}
	_, _ = io.Copy(w, resp.Body)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"error":{"message":%q}}`, msg)
}
