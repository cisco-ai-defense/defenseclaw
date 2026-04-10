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
	"fmt"
	"net/http"
)

// GenericConnector is the fallback connector that handles requests from
// any OpenAI-compatible client (curl, future frameworks, etc.).
//
// It uses the same provider resolution logic as ZeptoClaw (model prefix
// inference) but with relaxed authentication: loopback is always allowed
// regardless of gateway token configuration.
type GenericConnector struct {
	// providers maps provider name → upstream entry.
	providers map[string]ZCProviderEntry
}

// NewGenericConnector creates a Generic fallback connector.
// It reuses ZeptoClaw's provider defaults and config providers.
func NewGenericConnector(providers map[string]ZCProviderEntry) *GenericConnector {
	if providers == nil {
		providers = make(map[string]ZCProviderEntry)
	}
	return &GenericConnector{
		providers: providers,
	}
}

func (c *GenericConnector) Name() string { return "generic" }

// Detect always returns true — this is the fallback connector.
func (c *GenericConnector) Detect(*http.Request) bool { return true }

// Authenticate allows all loopback requests. Non-loopback requests are
// also allowed (the generic connector is intentionally permissive for
// development/testing use cases like curl).
func (c *GenericConnector) Authenticate(r *http.Request) bool {
	// Always allow loopback.
	if IsLoopback(r) {
		return true
	}
	// Allow non-loopback too — generic is permissive.
	// Operators who want stricter auth should use a specific connector.
	return true
}

// Route resolves the upstream URL using the same logic as ZeptoClaw:
// model prefix inference → config map → default provider table.
func (c *GenericConnector) Route(r *http.Request, body []byte) (*RoutingDecision, error) {
	var partial struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	_ = json.Unmarshal(body, &partial)

	providerName := InferProviderFromModel(partial.Model)
	if providerName == "" {
		return nil, fmt.Errorf("connector: generic: cannot determine provider from model %q", partial.Model)
	}

	entry, ok := c.providers[providerName]
	if !ok {
		entry, ok = ZeptoClawDefaultProviders[providerName]
		if !ok {
			return nil, fmt.Errorf("connector: generic: unknown provider %q", providerName)
		}
	}

	apiKey, _, _ := ExtractAPIKey(r, "sk-dc-")

	authHeader := entry.AuthHeader
	authScheme := entry.AuthScheme
	if authHeader == "" {
		authHeader = "Authorization"
		authScheme = "Bearer"
	}

	fullUpstreamURL := entry.UpstreamURL + r.URL.RequestURI()

	return &RoutingDecision{
		UpstreamURL:          fullUpstreamURL,
		ProviderName:         providerName,
		APIKey:               apiKey,
		AuthHeader:           authHeader,
		AuthScheme:           authScheme,
		Model:                partial.Model,
		Stream:               partial.Stream,
		RawBody:              body,
		PassthroughMode:      false,
		ExtraUpstreamHeaders: make(map[string]string),
		ConnectorName:        "generic",
	}, nil
}
