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

package extproc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAskGatewayUnreachableFollowsTheFailureMode (GAP-0168): a gateway that
// refuses the connection, or that does not answer before the hold ends,
// is an outage: the failure mode decides (closed refuses retryable, open
// allows with an alert), never "pending approval".
func TestAskGatewayUnreachableFollowsTheFailureMode(t *testing.T) {
	ctx := context.Background()
	// A port nothing listens on.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := "http://" + l.Addr().String()
	_ = l.Close()
	// A gateway that holds the connection past the ask hold.
	stall := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-stall }))
	defer slow.Close()
	defer close(stall)

	for name, base := range map[string]string{"refused": refused, "no answer in the hold": slow.URL} {
		t.Run(name, func(t *testing.T) {
			client := &AskClient{url: base + AskPath, http: &http.Client{}, poll: 10 * time.Millisecond}
			hctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			_, err := client.Ask(hctx, AskRequest{Actor: ActorRef{Atespace: "eng-web", Name: "a1", UID: "uid-1"}, Host: "files.example.io"})
			cancel()
			if !errors.Is(err, ErrAskUnreachable) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err %v", err)
			}
			for _, mode := range []string{FailureClosed, FailureOpen} {
				h := newHarness(t, func(c *Config, o *Options) {
					c.FailureMode = mode
					c.Ask.Hold = 100 * time.Millisecond
					o.Asks = client
				})
				v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "files.example.io", "/"))
				switch mode {
				case FailureClosed:
					if v.Allow || v.Category != CategoryCalloutError || !v.Retryable {
						t.Fatalf("closed: %+v", v)
					}
				case FailureOpen:
					if !v.Allow || !v.Alert {
						t.Fatalf("open: %+v", v)
					}
				}
			}
		})
	}
}
