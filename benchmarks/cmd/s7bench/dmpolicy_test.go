// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package main

import "testing"

func TestDMCorpusAllowed(t *testing.T) {
	ext := "https://dm.example.com/v1/systemone"
	cases := []struct {
		name, endpoint, corpus, allow string
		ok                            bool
	}{
		{"no endpoint", "", "agent-transcripts-sample", "", true},
		{"loopback stub needs no allowlist", "http://127.0.0.1:8791/v1/systemone", "agent-transcripts-sample", "", true},
		{"localhost stub", "http://localhost:8791/x", "s2", "", true},
		{"ipv6 loopback", "http://[::1]:8791/x", "s2", "", true},
		{"external, corpus listed", ext, "s2", "s2,s3", true},
		{"external, plus separator", ext, "s3", "s2+s3", true},
		{"external, corpus not listed", ext, "agent-transcripts-sample", "s2,s3", false},
		{"external, owner trace not listed", ext, "agent-transcripts-aidev-sample", "s2", false},
		{"external, empty allowlist", ext, "s2", "", false},
		{"external, star is not accepted", ext, "s2", "*", false},
		{"external, no corpus name", ext, "", "s2", false},
		{"look-alike host is external", "http://127.0.0.1.example.com/x", "s2", "", false},
	}
	for _, c := range cases {
		err := dmCorpusAllowed(c.endpoint, c.corpus, c.allow)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}
