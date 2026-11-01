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
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

type stopTestKey struct{}

// serveStopTest serves h on a loopback listener with the gateway's request
// base context built from runCtx.
func serveStopTest(t *testing.T, runCtx context.Context, h http.Handler) (*http.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, BaseContext: apiRequestBaseContext(runCtx)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, "http://" + ln.Addr().String()
}

// A gateway stop cancels its run context before the listeners shut down. A
// hook call the gateway already accepted must still get its answer inside
// the shutdown grace, not be read as a client that went away (GAP-1459:
// every per-user restart under load denied the calls in flight and audited
// them as blocks).
func TestGatewayStopLetsAnAcceptedHookCallAnswer(t *testing.T) {
	runCtx, stopRun := context.WithCancel(context.WithValue(context.Background(), stopTestKey{}, "run-value"))
	defer stopRun()
	started, release := make(chan struct{}), make(chan struct{})
	srv, url := serveStopTest(t, runCtx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
		}
		if r.Context().Err() != nil {
			http.Error(w, "cancelled", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "answered "+r.Context().Value(stopTestKey{}).(string))
	}))

	type result struct {
		status int
		body   string
		err    error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := http.Post(url+"/api/v1/claude-code/hook", "application/json", nil)
		if err != nil {
			got <- result{err: err}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		got <- result{status: resp.StatusCode, body: string(body)}
	}()
	<-started

	stopRun() // the sidecar cancels its run context first
	stopped := make(chan error, 1)
	go func() { stopped <- shutdownAPIServers(5*time.Second, srv, nil) }()
	time.Sleep(100 * time.Millisecond)
	close(release) // the decision completes during the stop

	r := <-got
	if r.err != nil || r.status != http.StatusOK || r.body != "answered run-value" {
		t.Fatalf("in-flight hook call during stop = status %d body %q err %v; want 200 \"answered run-value\"", r.status, r.body, r.err)
	}
	if err := <-stopped; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if _, err := http.Post(url+"/api/v1/claude-code/hook", "application/json", nil); err == nil {
		t.Fatal("the listener still accepted a call after the stop")
	}
}

// A request that outlives the grace (a follow stream) is closed with its
// connection, and the stop is still clean.
func TestGatewayStopClosesARequestThatOutlivesTheGrace(t *testing.T) {
	runCtx, stopRun := context.WithCancel(context.Background())
	defer stopRun()
	started, ended := make(chan struct{}), make(chan struct{})
	srv, url := serveStopTest(t, runCtx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(ended)
	}))
	go func() {
		resp, err := http.Get(url + "/api/v1/sandbox/events?follow=true")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	<-started
	stopRun()
	begin := time.Now()
	if err := shutdownAPIServers(200*time.Millisecond, srv); err != nil {
		t.Fatalf("shutdown after the grace: %v, want a clean stop", err)
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the follow request kept running after the grace")
	}
	if took := time.Since(begin); took > 3*time.Second {
		t.Fatalf("stop took %s, want about the 200ms grace", took)
	}
}
