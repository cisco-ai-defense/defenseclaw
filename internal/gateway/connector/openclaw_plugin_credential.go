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
	"strings"
	"sync"
)

// openClawPluginCredential is the connector-scoped token the OpenClaw plugin
// sends to the guardrail proxy (X-DC-Auth) and proves the proxy listener
// with. Setup records it from SetupOpts.HookAPIToken.
type openClawPluginCredential struct {
	mu    sync.RWMutex
	token string
}

func (p *openClawPluginCredential) set(token string) {
	p.mu.Lock()
	p.token = strings.TrimSpace(token)
	p.mu.Unlock()
}

func (p *openClawPluginCredential) get() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.token
}

// recordPluginCredential keeps the scoped credential Setup issued.
func (c *OpenClawConnector) recordPluginCredential(opts SetupOpts) {
	if opts.HookAPITokenScoped && strings.TrimSpace(opts.HookAPIToken) != "" {
		c.plugin.set(opts.HookAPIToken)
	}
}

// PluginProofToken is the credential the guardrail proxy also answers the
// plugin listener proof with, or "" before Setup issued one.
func (c *OpenClawConnector) PluginProofToken() string { return c.plugin.get() }

// pluginCredentialMatches accepts the plugin credential on loopback in
// X-DC-Auth: the fetch interceptor and egress telemetry send it there.
func (c *OpenClawConnector) pluginCredentialMatches(r *http.Request) bool {
	want := c.plugin.get()
	dcAuth := r.Header.Get("X-DC-Auth")
	if want == "" || dcAuth == "" || !IsLoopback(r) {
		return false
	}
	return SecureTokenMatch(strings.TrimPrefix(dcAuth, "Bearer "), want)
}
