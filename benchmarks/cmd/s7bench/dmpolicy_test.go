// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package main

import (
	"strings"
	"testing"
)

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

// A fill run takes no judge configuration (rel-1-0-10:GAP-0617): the unsure fill answers would escalate to the paid judge.
func TestDMFillRefusesAJudgeConfiguration(t *testing.T) {
	cases := []struct {
		name                    string
		fill                    bool
		judgeModel, judgeURL, l string
		refused                 bool
	}{
		{"fill, no judge", true, "", "", "", false},
		{"fill, dm layer only", true, "", "", "dm", false},
		{"fill, judge model", true, "gemma-4-31b", "", "", true},
		{"fill, judge url only", true, "", "http://127.0.0.1:9000/v1", "", true},
		{"fill, judge layer", true, "", "", "judge", true},
		{"fill, dm and judge layers", true, "", "", "dm,judge", true},
		{"fill, dm+judge layers", true, "", "", "dm+judge", true},
		{"fill, blank judge model", true, "  ", "", "", false},
		{"no fill, judge model", false, "gemma-4-31b", "http://127.0.0.1:9000/v1", "dm,judge", false},
	}
	for _, c := range cases {
		err := dmFillJudgeRefused(c.fill, c.judgeModel, c.judgeURL, c.l)
		if (err != nil) != c.refused {
			t.Errorf("%s: refused=%v, want %v (%v)", c.name, err != nil, c.refused, err)
		}
		if err != nil && !strings.Contains(err.Error(), "-dm-fill cannot run with a judge configuration") {
			t.Errorf("%s: error does not name the cause: %v", c.name, err)
		}
	}
}
