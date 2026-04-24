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
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// connectHandler wraps an http.Handler and intercepts HTTP CONNECT requests.
// For CONNECT, it establishes a TCP tunnel to the target host and relays
// bytes bidirectionally. All other methods are passed to the inner handler.
//
// This lets clients that use http.proxy as a forward proxy tunnel their TLS
// connections through DefenseClaw. The tunnel is opaque — we log the target
// host for audit but do not decrypt the traffic.
func connectHandler(inner http.Handler, logger interface {
	LogAction(action, target, details string) error
}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			inner.ServeHTTP(w, r)
			return
		}

		handleConnect(w, r, logger)
	})
}

func handleConnect(w http.ResponseWriter, r *http.Request, logger interface {
	LogAction(action, target, details string) error
}) {
	targetHost := r.Host
	if targetHost == "" {
		targetHost = r.URL.Host
	}
	if targetHost == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(os.Stderr, "[guardrail] CONNECT tunnel → %s (from %s)\n", targetHost, r.RemoteAddr)

	emitLifecycle(context.Background(), "connect-tunnel", "open", map[string]string{
		"target": targetHost,
		"remote": r.RemoteAddr,
	})

	if logger != nil {
		_ = logger.LogAction("connect-tunnel", targetHost, fmt.Sprintf("remote=%s", r.RemoteAddr))
	}

	targetConn, err := net.DialTimeout("tcp", targetHost, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] CONNECT dial failed: %s → %v\n", targetHost, err)
		http.Error(w, fmt.Sprintf("failed to connect to %s: %v", targetHost, err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		fmt.Fprintf(os.Stderr, "[guardrail] CONNECT failed: response writer does not support hijack\n")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] CONNECT hijack failed: %v\n", err)
		http.Error(w, fmt.Sprintf("hijack failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Send 200 Connection Established back to the client.
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Relay bytes bidirectionally.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, clientConn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, targetConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
	fmt.Fprintf(os.Stderr, "[guardrail] CONNECT tunnel closed: %s\n", targetHost)
}
