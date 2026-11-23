// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// The actor kit runs in Linux actor images only (kit.Config refuses other systems); its tests render and
// resolve paths for Linux.
//go:build linux

package kit

import "testing"

// TestRelayStreamsNeedTLS (S2b): port and mcp are known relay streams and
// ride TLS only; an unknown stream (an editor "code" stream included) is
// refused.
func TestRelayStreamsNeedTLS(t *testing.T) {
	v := "https://gw.example/api/v1/substrate/relay/verify"
	for _, tc := range []struct {
		streams []string
		ok      bool
	}{
		{[]string{StreamTLS, StreamPort, StreamMCP}, true},
		{[]string{StreamTLS, StreamPort}, true},
		{[]string{StreamPort}, false},
		{[]string{StreamMCP}, false},
		{[]string{StreamTLS, "code"}, false},
	} {
		err := RelayConfig{VerifyURL: v, Streams: tc.streams}.checkStreams()
		if (err == nil) != tc.ok {
			t.Errorf("%v: %v", tc.streams, err)
		}
	}
}
