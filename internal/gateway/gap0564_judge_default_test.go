// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestGAP0564JudgeParallelEndpointDefaults(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		local    bool
	}{
		{"loopback v4", "http://127.0.0.1:11434/v1", true},
		{"loopback v6", "http://[::1]:11434/v1", true},
		{"private v4", "http://10.2.3.4:11434/v1", true},
		{"private v6", "http://[fd00::2]:11434/v1", true},
		{"link local v4", "http://169.254.1.2:11434/v1", true},
		{"link local v6", "http://[fe80::2]:11434/v1", true},
		{"localhost name", "http://model.localhost:11434/v1", true},
		{"localhost localdomain", "http://localhost.localdomain:11434/v1", true},
		{"public", "https://api.example.test/v1", false},
		{"lookalike", "https://localhost.example.test/v1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := localJudgeEndpoint(tc.endpoint); got != tc.local {
				t.Fatalf("localJudgeEndpoint(%q)=%t, want %t", tc.endpoint, got, tc.local)
			}
			llm := config.LLMConfig{Provider: "openai", Model: "openai/test", BaseURL: tc.endpoint}
			want := 0
			if tc.local {
				want = 1
			}
			if got := judgeParallelLimit(&config.JudgeConfig{}, llm, tc.endpoint); got != want {
				t.Fatalf("implicit parallel limit=%d, want %d", got, want)
			}
			if got := judgeParallelLimit(&config.JudgeConfig{MaxParallel: 3, MaxParallelExplicit: true}, llm, tc.endpoint); got != 3 {
				t.Fatalf("explicit parallel limit=%d, want 3", got)
			}
			if got := judgeParallelLimit(&config.JudgeConfig{MaxParallelExplicit: true}, llm, tc.endpoint); got != 0 {
				t.Fatalf("explicit unlimited limit=%d, want 0", got)
			}
		})
	}
}

// The default is applied at judge construction, including the shared
// scheduler used by hook and proxy calls. Public endpoints retain no limit.
func TestGAP0564ConstructedJudgeUsesEndpointDefault(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		want     int
	}{
		{"local", "http://localhost:11435/v1", 1},
		{"public", "https://api.example.test/gap0564", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.JudgeConfig{Enabled: true}
			llm := config.LLMConfig{
				Provider: "openai", Model: "openai/test", APIKey: "test-placeholder", BaseURL: tc.endpoint,
			}
			judge := NewLLMJudge(cfg, llm, "", nil, nil)
			if judge == nil {
				t.Fatal("judge was not created")
			}
			if tc.want == 0 {
				if judge.calls != nil {
					t.Fatalf("public endpoint got scheduler limit %d", judge.calls.limit)
				}
				return
			}
			if judge.calls == nil || judge.calls.limit != tc.want {
				t.Fatalf("local endpoint scheduler=%v, want limit %d", judge.calls, tc.want)
			}
		})
	}
}

func TestGAP0564CancelledJudgeDoesNotStartQueuedCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &judgeScheduler{limit: 1}
	if release, err := s.acquire(ctx, judgeCallContent); err != context.Canceled || release != nil {
		t.Fatalf("cancelled acquire returned release=%v err=%v", release != nil, err)
	}
}
