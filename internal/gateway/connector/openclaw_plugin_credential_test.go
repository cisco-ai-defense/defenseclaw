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
	"net/http/httptest"
	"strings"
	"testing"
)

// The guardrail proxy accepts the plugin credential Setup issued, on
// loopback only; a gateway that issued none accepts nothing new.
func TestOpenClawAuthenticateAcceptsThePluginCredential(t *testing.T) {
	c := NewOpenClawConnector()
	c.SetCredentials("master-token", "")
	plugin := strings.Repeat("a", 64)
	req := func(remote, token string) bool {
		r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-DC-Auth", "Bearer "+token)
		return c.Authenticate(r)
	}
	if req("127.0.0.1:5000", plugin) {
		t.Fatal("plugin credential accepted before Setup issued it")
	}
	c.recordPluginCredential(SetupOpts{HookAPIToken: plugin, HookAPITokenScoped: true})
	if !req("127.0.0.1:5000", plugin) {
		t.Fatal("plugin credential refused on loopback")
	}
	if c.PluginProofToken() != plugin {
		t.Fatal("PluginProofToken does not name the issued credential")
	}
	if req("127.0.0.1:5000", strings.Repeat("b", 64)) {
		t.Fatal("another token accepted")
	}
	c.recordPluginCredential(SetupOpts{HookAPIToken: "master-token", HookAPITokenScoped: false})
	if c.PluginProofToken() != plugin {
		t.Fatal("an unscoped token replaced the plugin credential")
	}
}
