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
	"net/http"
	"net/url"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/configs"
)

// ProviderDomain maps a domain substring to a canonical provider name.
type ProviderDomain struct {
	Domain string
	Name   string
}

// providerDomains is built once from the embedded providers.json.
var providerDomains []ProviderDomain

func init() {
	cfg, err := configs.LoadProviders()
	if err != nil {
		panic("connector: failed to load embedded providers.json: " + err.Error())
	}
	for _, p := range cfg.Providers {
		for _, d := range p.Domains {
			providerDomains = append(providerDomains, ProviderDomain{Domain: d, Name: p.Name})
		}
	}
}

// InferProviderFromURL maps a target URL to a provider name by checking
// domain substrings from the embedded providers.json.
func InferProviderFromURL(targetURL string) string {
	for _, pd := range providerDomains {
		if strings.Contains(targetURL, pd.Domain) {
			return pd.Name
		}
	}
	return ""
}

// IsKnownProviderDomain returns true when the hostname of targetURL contains
// a domain substring from the embedded providers.json list. Only the parsed
// hostname is checked — query strings and path components are ignored to
// prevent bypass via crafted URLs like https://evil.com/?foo=api.openai.com.
func IsKnownProviderDomain(targetURL string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	for _, pd := range providerDomains {
		if strings.Contains(host, pd.Domain) {
			return true
		}
	}
	return false
}

// ScrubURLSecrets removes sensitive query parameters (key, api-key, apikey,
// token) from a URL string before logging. Returns the original string
// unmodified when it contains no query string.
func ScrubURLSecrets(raw string) string {
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

// ExtractAPIKey extracts the API key from the request headers, checking
// multiple header patterns used by different providers:
//   - X-AI-Auth: "Bearer <key>" (set by OpenClaw fetch interceptor)
//   - Authorization: "Bearer <key>" (standard)
//   - x-api-key: "<key>" (Anthropic)
//   - api-key: "<key>" (Azure)
//
// The masterKeyPrefix parameter (e.g. "sk-dc-") is used to skip proxy
// master keys that shouldn't be forwarded upstream.
func ExtractAPIKey(r *http.Request, masterKeyPrefix string) (key string, headerName string, scheme string) {
	// Priority 1: X-AI-Auth from the fetch interceptor.
	if aiAuth := r.Header.Get("X-AI-Auth"); aiAuth != "" {
		if strings.HasPrefix(aiAuth, "Bearer ") {
			k := strings.TrimPrefix(aiAuth, "Bearer ")
			if !strings.HasPrefix(k, masterKeyPrefix) {
				return k, "Authorization", "Bearer"
			}
		}
	}

	// Priority 2: api-key (Azure).
	if azKey := r.Header.Get("api-key"); azKey != "" {
		return azKey, "api-key", ""
	}

	// Priority 3: x-api-key (Anthropic).
	if xKey := r.Header.Get("x-api-key"); xKey != "" {
		return xKey, "x-api-key", ""
	}

	// Priority 4: Authorization (standard Bearer).
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			k := strings.TrimPrefix(auth, "Bearer ")
			if !strings.HasPrefix(k, masterKeyPrefix) {
				return k, "Authorization", "Bearer"
			}
		}
	}

	return "", "", ""
}

// IsLoopback returns true if the request originates from the loopback interface.
func IsLoopback(r *http.Request) bool {
	return strings.HasPrefix(r.RemoteAddr, "127.0.0.1:") || strings.HasPrefix(r.RemoteAddr, "[::1]:")
}
