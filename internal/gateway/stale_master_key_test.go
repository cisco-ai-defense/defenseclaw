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

package gateway

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/crypto/pbkdf2"
)

// TestProxyRejectsStaleDeviceKeyMasterKey pins the 1.0.10 removal: the
// sk-dc- value earlier releases derived from device.key is not a credential,
// with or without a connector wired to the proxy.
func TestProxyRejectsStaleDeviceKeyMasterKey(t *testing.T) {
	dk := pbkdf2.Key([]byte("device-key-bytes"), []byte("defenseclaw-proxy-master-key"), 100_000, 32, sha256.New)
	stale := "sk-dc-" + fmt.Sprintf("%x", dk)

	newReq := func(h http.Header) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		r.RemoteAddr = "127.0.0.1:12345"
		for k, v := range h {
			r.Header[k] = v
		}
		return r
	}

	p := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	p.skipAuthForTest = false
	p.gatewayToken = "gateway-token-for-test"

	if p.credentialsAccepted(newReq(http.Header{"Authorization": {"Bearer " + stale}})) {
		t.Fatal("proxy without a connector accepted the stale sk-dc- master key")
	}
	if p.presentsOwnerCredential(newReq(http.Header{"Authorization": {"Bearer " + stale}})) {
		t.Fatal("stale sk-dc- master key counted as an owner credential")
	}
	if !p.credentialsAccepted(newReq(http.Header{"X-Dc-Auth": {"Bearer gateway-token-for-test"}})) {
		t.Fatal("the gateway token must still authenticate")
	}

	p.connector = connector.NewClaudeCodeConnector()
	p.connector.SetCredentials(p.gatewayToken)
	if p.credentialsAccepted(newReq(http.Header{"Authorization": {"Bearer " + stale}})) {
		t.Fatal("proxy with a connector accepted the stale sk-dc- master key")
	}
}
