// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type fakeChecker struct {
	calls atomic.Int32
	yes   bool
	err   error
	delay time.Duration
}

func (f *fakeChecker) Name() string { return "decision_model" }

func (f *fakeChecker) Check(ctx context.Context, in SensitiveInput) (bool, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return false, &ClassifierError{Code: FailureTimeout, Err: ctx.Err()}
		}
	}
	return f.yes, f.err
}

func checkEngine(t *testing.T, s config.RoutingSensitiveConfig, f *fakeChecker) *Engine {
	t.Helper()
	cfg := testConfig()
	cfg.Routing.Sensitive = &s
	return mustEngine(t, cfg, Options{SensitiveChecker: f})
}

func checkReq(text string) Request {
	r := chat("please refactor this")
	r.SensitiveText = text
	r.ConversationID = "c1"
	return r
}

func TestSensitiveCheckPositiveRoutesLocalAndSticks(t *testing.T) {
	f := &fakeChecker{yes: true}
	e := checkEngine(t, config.RoutingSensitiveConfig{Check: "decision_model", Aliases: []string{"local"}}, f)
	d := e.Decide(context.Background(), checkReq("my diagnosis is x"))
	if d.Backend == nil || d.Backend.Alias != "local" || d.Sensitive.Source != "decision_model" || d.Sensitive.Reason != "positive" || !d.Sensitive.Checked {
		t.Fatalf("decision = %+v %+v", d, d.Sensitive)
	}
	d = e.Decide(context.Background(), checkReq("continue"))
	if d.Backend.Alias != "local" || d.Sensitive.Source != SensitiveSourceSticky || f.calls.Load() != 1 {
		t.Fatalf("second call = %+v calls %d", d.Sensitive, f.calls.Load())
	}
}

func TestSensitiveCheckClearKeepsRoute(t *testing.T) {
	f := &fakeChecker{}
	e := checkEngine(t, config.RoutingSensitiveConfig{Check: "decision_model", Aliases: []string{"local"}}, f)
	d := e.Decide(context.Background(), checkReq("benign"))
	if d.Backend.Alias != "claude" || d.Sensitive.Source != "" || d.Sensitive.Reason != "clear" {
		t.Fatalf("decision = %+v %+v", d.Backend, d.Sensitive)
	}
}

func TestSensitiveFloorSkipsTheCheck(t *testing.T) {
	f := &fakeChecker{}
	e := checkEngine(t, config.RoutingSensitiveConfig{Check: "decision_model", SeverityAtLeast: "HIGH", Aliases: []string{"local"}}, f)
	r := checkReq("x")
	r.Severity = "HIGH"
	d := e.Decide(context.Background(), r)
	if d.Backend.Alias != "local" || d.Sensitive.Source != SensitiveSourceGuardrail || f.calls.Load() != 0 {
		t.Fatalf("decision = %+v calls %d", d.Sensitive, f.calls.Load())
	}
}

func TestSensitiveCheckOffNeverCalls(t *testing.T) {
	f := &fakeChecker{yes: true}
	e := checkEngine(t, config.RoutingSensitiveConfig{Check: "off", SeverityAtLeast: "HIGH", Aliases: []string{"local"}}, f)
	d := e.Decide(context.Background(), checkReq("anything"))
	if d.Backend.Alias != "claude" || f.calls.Load() != 0 || d.Sensitive.Checked {
		t.Fatalf("check off ran: %+v calls %d", d.Sensitive, f.calls.Load())
	}
}

func TestSensitiveCheckUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		s       config.RoutingSensitiveConfig
		f       *fakeChecker
		want    string
		source  string
		failure string
	}{
		{"error goes local", config.RoutingSensitiveConfig{Check: "judge", Aliases: []string{"local"}}, &fakeChecker{err: &ClassifierError{Code: FailureUpstreamStatus}}, "local", "decision_model", FailureUpstreamStatus},
		{"slow goes local", config.RoutingSensitiveConfig{Check: "judge", TimeoutMs: 50, Aliases: []string{"local"}}, &fakeChecker{delay: 2 * time.Second}, "local", "decision_model", FailureTimeout},
		{"plain error counts as config failure", config.RoutingSensitiveConfig{Check: "judge", Aliases: []string{"local"}}, &fakeChecker{err: errors.New("boom")}, "local", "decision_model", FailureConfig},
		{"ignore keeps the route", config.RoutingSensitiveConfig{Check: "judge", OnUnavailable: "ignore", Aliases: []string{"local"}}, &fakeChecker{err: &ClassifierError{Code: FailureTimeout}}, "claude", "", FailureTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := checkEngine(t, tc.s, tc.f)
			d := e.Decide(context.Background(), checkReq("text"))
			if d.Outcome != OutcomeApplied || d.Backend.Alias != tc.want || d.Sensitive.Source != tc.source || d.Sensitive.CheckFailure != tc.failure {
				t.Fatalf("decision = %+v backend %+v", d.Sensitive, d.Backend)
			}
		})
	}
}

func TestSensitiveUnavailableWithoutLocalRouteNeverBlocks(t *testing.T) {
	cfg := testConfig()
	cfg.Routing.Sensitive = &config.RoutingSensitiveConfig{Check: "judge", Aliases: []string{"local"}}
	cfg.Routing.Admin = &config.RoutingAdminConfig{AllowedAliases: []string{"claude", "fast"}}
	e := mustEngine(t, cfg, Options{SensitiveChecker: &fakeChecker{err: &ClassifierError{Code: FailureTimeout}}})
	d := e.Decide(context.Background(), checkReq("text"))
	if d.Outcome != OutcomeApplied || d.Backend.Alias != "claude" || d.Sensitive.Source != "" || d.Sensitive.Reason != "unavailable:timeout:no_local_route" {
		t.Fatalf("decision = %+v %+v", d.Backend, d.Sensitive)
	}
}

func TestSensitiveTruncatedFollowsTheTier(t *testing.T) {
	for _, strict := range []bool{false, true} {
		e := checkEngine(t, config.RoutingSensitiveConfig{Check: "decision_model", Aliases: []string{"local"}}, &fakeChecker{})
		r := checkReq("text")
		r.SensitiveTruncated, r.StrictTier = true, strict
		d := e.Decide(context.Background(), r)
		wantLocal := strict
		if (d.Backend.Alias == "local") != wantLocal || d.Sensitive.Reason != "truncated" || len(d.Warnings) == 0 {
			t.Fatalf("strict=%v decision = %+v %+v warnings %v", strict, d.Backend, d.Sensitive, d.Warnings)
		}
	}
}

func TestSensitiveCheckClearAnswerIsReusedForTheSameText(t *testing.T) {
	f := &fakeChecker{}
	e := checkEngine(t, config.RoutingSensitiveConfig{Check: "decision_model", Aliases: []string{"local"}}, f)
	e.Decide(context.Background(), checkReq("benign text"))
	d := e.Decide(context.Background(), checkReq("benign text"))
	if f.calls.Load() != 1 || d.Sensitive.Reason != "clear_cached" {
		t.Fatalf("same text asked again: calls %d %+v", f.calls.Load(), d.Sensitive)
	}
	e.Decide(context.Background(), checkReq("new text"))
	if f.calls.Load() != 2 {
		t.Fatalf("new text not asked: calls %d", f.calls.Load())
	}
}
