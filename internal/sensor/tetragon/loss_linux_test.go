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

//go:build linux

package tetragon

import (
	"context"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
)

// TestLossCountersOnlyFromTetragonsOwnLoopbackListener: the scrape happens
// only on a loopback address whose listener belongs to the info file's pid.
func TestLossCountersOnlyFromTetragonsOwnLoopbackListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback TCP: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tetragon_notify_overflowed_events_total 10\ntetragon_bpf_missed_events_total{msg_op=\"5\"} 2\n"))
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	address := listener.Addr().String()
	_, port, _ := net.SplitHostPort(address)
	portNumber, _ := strconv.Atoi(port)

	if err := listenerOwnedBy(portNumber, os.Getpid()); err != nil {
		t.Fatalf("own listener: %v", err)
	}
	total, err := readLossCounters(context.Background(), Info{MetricsAddress: address, PID: os.Getpid()})
	if err != nil || total != 12 {
		t.Fatalf("scrape: %d %v", total, err)
	}
	// Another pid's listener on the port is not Tetragon's.
	if _, err := readLossCounters(context.Background(), Info{MetricsAddress: address, PID: 1}); err == nil {
		t.Fatal("scraped a listener that is not the Tetragon pid's")
	}
	for _, bad := range []string{":" + port, "0.0.0.0:" + port, "10.0.0.1:" + port, "localhost:" + port, "127.0.0.1"} {
		if _, err := readLossCounters(context.Background(), Info{MetricsAddress: bad, PID: os.Getpid()}); err == nil {
			t.Fatalf("scraped %q", bad)
		}
	}
}
