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
)

// Router holds an ordered list of connectors and resolves incoming requests
// to the first matching connector. If no connector matches, the fallback is used.
type Router struct {
	connectors []Connector
	fallback   Connector
}

// NewRouter creates a Router with the given connectors checked in order.
// Detection order matters: more specific connectors (OpenClaw with its
// X-DC-Target-URL header) should come before more general ones (ZeptoClaw,
// Generic).
func NewRouter(connectors ...Connector) *Router {
	return &Router{
		connectors: connectors,
	}
}

// SetFallback sets the fallback connector used when no other connector
// matches the request. Typically this is the Generic connector.
func (r *Router) SetFallback(c Connector) {
	r.fallback = c
}

// Resolve returns the first connector whose Detect method returns true for
// the given request. If no connector matches, the fallback is returned.
// Returns nil only if no connectors are registered and no fallback is set.
func (r *Router) Resolve(req *http.Request) Connector {
	for _, c := range r.connectors {
		if c.Detect(req) {
			return c
		}
	}
	return r.fallback
}

// ConnectorNames returns the names of all registered connectors (including
// the fallback) for diagnostic/logging purposes.
func (r *Router) ConnectorNames() []string {
	names := make([]string, 0, len(r.connectors)+1)
	for _, c := range r.connectors {
		names = append(names, c.Name())
	}
	if r.fallback != nil {
		names = append(names, r.fallback.Name()+" (fallback)")
	}
	return names
}
