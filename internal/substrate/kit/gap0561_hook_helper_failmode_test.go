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

package kit

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// substrate-1 GAP-0554 / GAP-0561 (scope check): what the actor's hook helper
// answers for a benign Claude Code PreToolUse when the gateway errors, through
// the real RunHook and the real HTTP transport (no Send stub). D8: managed and
// unattended are closed; an OSS interactive actor follows the gateway's
// X-DefenseClaw-Fail-Mode for an outage (502/503/504) and the kit's own
// fail_mode (closed by default) when the gateway never answers; any other
// status, a 500 included, is a closed refusal.
func TestHookHelperGatewayErrorVerdicts(t *testing.T) {
	type gw struct {
		name     string
		handler  http.HandlerFunc
		closeNow bool // the server accepts and closes the connection
		timeout  bool // the server never answers within the transport's budget
	}
	errorGateways := []gw{
		{name: "500", handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }},
		{name: "500 open header", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(FailModeHeader, "open")
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{name: "503 closed header (managed)", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(FailModeHeader, "closed")
			w.WriteHeader(http.StatusServiceUnavailable)
		}},
		{name: "503 no header", handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }},
		{name: "connection closed", closeNow: true},
		{name: "timeout", timeout: true},
	}
	for _, g := range errorGateways {
		t.Run(g.name, func(t *testing.T) {
			url := ""
			switch {
			case g.closeNow:
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { ln.Close() })
				go func() {
					for {
						c, err := ln.Accept()
						if err != nil {
							return
						}
						c.Close()
					}
				}()
				url = "http://" + ln.Addr().String()
			case g.timeout:
				done := make(chan struct{})
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					select {
					case <-done:
					case <-r.Context().Done():
					}
				}))
				t.Cleanup(func() { close(done); srv.Close() })
				url = srv.URL
			default:
				srv := httptest.NewServer(g.handler)
				t.Cleanup(srv.Close)
				url = srv.URL
			}
			cfg := testConfig(url)
			cfg.MaxTimeMS, cfg.RetryMaxTimeMS, cfg.ConnectTimeoutMS = 400, 400, 200
			var out, errb bytes.Buffer
			start := time.Now()
			code := RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: cfg,
				Stdin: strings.NewReader(ccPre), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" }})
			allowed := code == 0 && !strings.Contains(out.String(), `"deny"`)
			t.Logf("VERDICT %-28s exit=%d allowed=%v took=%s stdout=%.160q", g.name, code, allowed, time.Since(start).Round(time.Millisecond), out.String())
			if allowed {
				t.Errorf("%s: a benign PreToolUse was allowed while the gateway failed (kit fail_mode %q)", g.name, cfg.FailMode)
			}
		})
	}
	// The one designed open case: an OSS interactive actor whose gateway
	// says fail-open answers an outage (503) with an allow and a warning.
	t.Run("503 open header (OSS interactive, D8)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(FailModeHeader, "open")
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		t.Cleanup(srv.Close)
		var out, errb bytes.Buffer
		code := RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: testConfig(srv.URL),
			Stdin: strings.NewReader(ccPre), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" }})
		t.Logf("VERDICT %-28s exit=%d stdout=%.160q stderr=%.160q", "503 open header", code, out.String(), errb.String())
	})
}
