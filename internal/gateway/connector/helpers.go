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

package connector

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// ExtractBearerKey extracts the API key from an Authorization header value,
// stripping the "Bearer " prefix. Returns empty string if no key found.
func ExtractBearerKey(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "Bearer ") {
		return strings.TrimSpace(value[7:])
	}
	if strings.HasPrefix(value, "bearer ") {
		return strings.TrimSpace(value[7:])
	}
	return value
}

// ExtractAPIKey extracts the upstream API key from an HTTP request using a
// priority chain common across connectors. Returns the raw key (no "Bearer "
// prefix).
//
// Priority:
//  1. X-AI-Auth header (OpenClaw fetch interceptor, normalized to "Bearer <key>")
//  2. api-key header (Azure)
//  3. x-api-key header (Anthropic)
//  4. Authorization header
//
// Keys prefixed with "sk-dc-" (DefenseClaw master keys) are skipped so they
// don't leak upstream.
func ExtractAPIKey(r *http.Request) string {
	if aiAuth := r.Header.Get("X-AI-Auth"); aiAuth != "" {
		key := ExtractBearerKey(aiAuth)
		if !strings.HasPrefix(key, "sk-dc-") {
			return key
		}
	}
	if azKey := r.Header.Get("api-key"); azKey != "" {
		return azKey
	}
	if xKey := r.Header.Get("x-api-key"); xKey != "" {
		return xKey
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		key := ExtractBearerKey(auth)
		if !strings.HasPrefix(key, "sk-dc-") {
			return key
		}
	}
	return ""
}

// chatBody is the minimal shape of an OpenAI/Anthropic chat request body
// used by ParseModelFromBody and ParseStreamFromBody.
type chatBody struct {
	Model  string `json:"model"`
	Stream *bool  `json:"stream,omitempty"`
}

// ParseModelFromBody extracts the "model" field from a JSON request body.
func ParseModelFromBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var b chatBody
	if err := json.Unmarshal(body, &b); err != nil {
		return ""
	}
	return b.Model
}

// ParseStreamFromBody extracts the "stream" field from a JSON request body.
// Returns false if the field is absent or unparseable.
func ParseStreamFromBody(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var b chatBody
	if err := json.Unmarshal(body, &b); err != nil {
		return false
	}
	if b.Stream == nil {
		return false
	}
	return *b.Stream
}

// IsLoopback returns true when the request originates from a loopback address.
func IsLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}

// isChatPath returns true for paths that are OpenAI/Anthropic chat completions.
func isChatPath(path string) bool {
	return strings.Contains(path, "/chat/completions") ||
		strings.Contains(path, "/messages") ||
		strings.Contains(path, "/responses")
}
