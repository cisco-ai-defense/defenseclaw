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
	"errors"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// GAP-0594: the sidecar writes no byte to a loopback OpenClaw listener that
// another account holds, and names the step.
func TestConnectRefusesAnOpenClawListenerOfAnotherAccount(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the listener account is checked on Linux and macOS")
	}
	var requests atomic.Int32
	srv := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	previous := verifyOpenClawListener
	verifyOpenClawListener = func(net.Conn) error { return errors.New("connected local peer belongs to uid 4242") }
	t.Cleanup(func() { verifyOpenClawListener = previous })

	client := clientForServer(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.Connect(ctx)
	if !errors.Is(err, errOpenClawListenerUnverified) {
		t.Fatalf("Connect error = %v, want the unverified listener", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("the listener received %d HTTP requests, want none", got)
	}
	if hint := client.handleConnectRejection(err); hint != openClawListenerUnverifiedHint || !strings.Contains(hint, "keeps retrying") {
		t.Fatalf("hint = %q, want the listener step", hint)
	}
}

// The real check accepts this account's own OpenClaw listener: every mock
// gateway test connects through it on Linux and macOS.
func TestConnectAcceptsThisAccountsOpenClawListener(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the listener account is checked on Linux and macOS")
	}
	var checked atomic.Int32
	previous := verifyOpenClawListener
	verifyOpenClawListener = func(conn net.Conn) error {
		checked.Add(1)
		return previous(conn)
	}
	t.Cleanup(func() { verifyOpenClawListener = previous })
	srv := startMockGW(t, nil)
	connectToMockGW(t, srv)
	if checked.Load() == 0 {
		t.Fatal("the loopback listener was not checked")
	}
}
