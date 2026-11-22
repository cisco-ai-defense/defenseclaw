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
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// staleMasterKey is the value releases before 1.0.10 derived from device.key
// (PBKDF2-SHA256, 100k rounds) and accepted as a bearer. No code derives it
// any more; tests use it to prove it is not a credential.
var staleMasterKey = func() string {
	dk := pbkdf2.Key([]byte("device-key-bytes"), []byte("defenseclaw-proxy-master-key"), 100_000, 32, sha256.New)
	return "sk-dc-" + fmt.Sprintf("%x", dk)
}()

func TestStaleMasterKeyIsNotACredentialForAnyConnector(t *testing.T) {
	const gatewayToken = "gateway-token-for-test"
	for _, conn := range []Connector{
		NewClaudeCodeConnector(),
		NewCodexConnector(),
		NewOpenClawConnector(),
		NewZeptoClawConnector(),
		NewAMPConnector(),
		NewKiroConnector(),
		NewCursorConnector(),
		NewHermesConnector(),
	} {
		conn.SetCredentials(gatewayToken)
		for _, remote := range []string{"10.0.0.5:54321", "127.0.0.1:54321"} {
			if remote == "127.0.0.1:54321" && (conn.Name() == "amp" || conn.Name() == "kiro" || conn.Name() == "cursor" || conn.Name() == "hermes") {
				// Hook-bridge connectors keep their documented legacy
				// loopback acceptance; the credential check is what this
				// test pins, so only probe them off-loopback.
				continue
			}
			r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			r.RemoteAddr = remote
			r.Header.Set("Authorization", "Bearer "+staleMasterKey)
			if conn.Authenticate(r) {
				t.Errorf("%s from %s: a stale sk-dc- master key authenticated", conn.Name(), remote)
			}
		}
		ok := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		ok.RemoteAddr = "10.0.0.5:54321"
		ok.Header.Set("X-DC-Auth", gatewayToken)
		ok.Header.Set("Authorization", "Bearer "+gatewayToken)
		if !conn.Authenticate(ok) {
			t.Errorf("%s: the gateway token must still authenticate", conn.Name())
		}
	}
}
