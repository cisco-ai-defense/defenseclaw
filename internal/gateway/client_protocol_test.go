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
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestConnectAdvertisesProtocolRange3To4 verifies that the connect handshake
// advertises support for gateway protocol v4 while remaining backward
// compatible with v3 gateways, i.e. [minProtocol, maxProtocol] = [3, 4].
//
// A gateway accepts any client range that includes its own protocol version,
// so this range negotiates successfully with both v3 and v4 gateways. A v4
// gateway (e.g. OpenClaw 2026.5.x) rejects a client that advertises only v3
// with INVALID_REQUEST / "protocol mismatch" and closes the socket (1002),
// which is the regression this guards against.
func TestConnectAdvertisesProtocolRange3To4(t *testing.T) {
	type connectParams struct {
		MinProtocol int `json:"minProtocol"`
		MaxProtocol int `json:"maxProtocol"`
	}
	gotParams := make(chan connectParams, 1)

	srv := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// 1) issue the connect challenge
		cp, _ := json.Marshal(ChallengePayload{Nonce: "test-nonce-abc", Ts: 1700000000000})
		challenge, _ := json.Marshal(EventFrame{Type: "event", Event: "connect.challenge", Payload: cp})
		_ = conn.WriteMessage(websocket.TextMessage, challenge)

		// 2) read the connect request and capture the advertised protocol range
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var req struct {
			ID     string        `json:"id"`
			Method string        `json:"method"`
			Params connectParams `json:"params"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return
		}
		gotParams <- req.Params

		// 3) accept with a v4 hello-ok so Connect() can complete
		helloData, _ := json.Marshal(HelloOK{Type: "hello-ok", Protocol: 4})
		resp, _ := json.Marshal(ResponseFrame{Type: "res", ID: req.ID, OK: true, Payload: helloData})
		_ = conn.WriteMessage(websocket.TextMessage, resp)
	}))

	client := clientForServer(t, srv)
	go func() { _ = client.Connect(context.Background()) }()

	select {
	case p := <-gotParams:
		if p.MinProtocol != 3 {
			t.Errorf("connect advertised minProtocol = %d, want 3", p.MinProtocol)
		}
		if p.MaxProtocol != 4 {
			t.Errorf("connect advertised maxProtocol = %d, want 4 (range must include v4)", p.MaxProtocol)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the client to send its connect frame")
	}
}
