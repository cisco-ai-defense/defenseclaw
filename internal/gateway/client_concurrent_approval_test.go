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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestGAP0709ApprovalResolvesShareSingleWriter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		callers int
		idSize  int
	}{
		{name: "sequential", callers: 1, idSize: 12},
		{name: "concurrent", callers: 32, idSize: 32 * 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan string, tc.callers)
			srv := startMockGW(t, func(t *testing.T, conn *websocket.Conn) {
				for {
					_, raw, err := conn.ReadMessage()
					if err != nil {
						return
					}
					var req RequestFrame
					if err := json.Unmarshal(raw, &req); err != nil {
						t.Errorf("decode request: %v", err)
						return
					}
					if req.Method != "exec.approval.resolve" {
						t.Errorf("method = %q", req.Method)
						return
					}
					params, err := json.Marshal(req.Params)
					if err != nil {
						t.Errorf("encode params: %v", err)
						return
					}
					var approval ApprovalResolveParams
					if err := json.Unmarshal(params, &approval); err != nil {
						t.Errorf("decode params: %v", err)
						return
					}
					received <- approval.ID
					resp, err := json.Marshal(ResponseFrame{Type: "res", ID: req.ID, OK: true})
					if err != nil {
						t.Errorf("encode response: %v", err)
						return
					}
					if err := conn.WriteMessage(websocket.TextMessage, resp); err != nil {
						return
					}
				}
			})
			client := connectToMockGW(t, srv)

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			start := make(chan struct{})
			results := make(chan error, tc.callers)
			want := make(map[string]bool, tc.callers)
			for i := 0; i < tc.callers; i++ {
				id := fmt.Sprintf("approval-%d-", i) + strings.Repeat("a", tc.idSize)
				want[id] = true
				go func() {
					<-start
					results <- client.ResolveApproval(ctx, id, true, "routine approval")
				}()
			}
			close(start)
			for i := 0; i < tc.callers; i++ {
				if err := <-results; err != nil {
					t.Errorf("resolve failed: %.160s", err)
				}
			}
			for i := 0; i < tc.callers; i++ {
				select {
				case id := <-received:
					if !want[id] {
						t.Error("unexpected or duplicate approval ID")
					}
					delete(want, id)
				case <-ctx.Done():
					t.Fatalf("received %d of %d approvals: %v", i, tc.callers, ctx.Err())
				}
			}
		})
	}
}

func TestGAP0709FailedWriteDisconnectsClient(t *testing.T) {
	srv := startMockGW(t, rpcEchoLoop)
	client := connectToMockGW(t, srv)
	disconnected := client.Disconnected()

	client.mu.Lock()
	conn := client.conn
	client.mu.Unlock()
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.ResolveApproval(ctx, "approval-write-error", true, "routine approval"); err == nil {
		t.Fatal("expected a write error")
	}
	select {
	case <-disconnected:
	case <-ctx.Done():
		t.Fatalf("failed write did not disconnect the client: %v", ctx.Err())
	}
}
