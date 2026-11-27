// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"strings"
	"testing"
	"time"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

// TestGAP0635CalloutLimitsEachActorsRate is substrate-1:GAP-0635: one actor
// past its burst (twice rate_limits.per_actor_rps) is refused with 429 and
// Retry-After, category rate_limited; another actor of the same atespace,
// and the same actor a second later, still get through; requests to the
// DefenseClaw actor listener are not charged.
func TestGAP0635CalloutLimitsEachActorsRate(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	h := newHarness(t, func(c *Config, o *Options) {
		c.RateLimits.PerActorRPS = 5
		c.DefenseClawHosts = append(c.DefenseClawHosts, "gw.dc.svc.cluster.local")
		o.Now = func() time.Time { return now }
	})
	ctx := context.Background()
	get := func(name, host string) Verdict {
		r := req("other", "GET", host, "/")
		r.Actor.Name = name
		return h.eng.DecideHeaders(ctx, r)
	}
	for i := range 10 {
		if v := get("a1", "example.com"); !v.Allow {
			t.Fatalf("request %d within the burst: %+v", i+1, v)
		}
	}
	for range 5 {
		if v := get("a1", "gw.dc.svc.cluster.local"); !v.Allow || !v.OwnHost {
			t.Fatalf("own host: %+v", v)
		}
	}
	v := get("a1", "example.com")
	if v.Allow || !v.TooMany || v.Category != CategoryRateLimited || v.Rule != "rate_limits.per_actor_rps" {
		t.Fatalf("past the burst: %+v (want a rate_limited refusal)", v)
	}
	resp := h.eng.immediate(req("other", "GET", "example.com", "/"), v).GetImmediateResponse()
	retry := false
	for _, hv := range resp.GetHeaders().GetSetHeaders() {
		retry = retry || (hv.GetHeader().GetKey() == "retry-after" && string(hv.GetHeader().GetRawValue()) == "1")
	}
	if resp.GetStatus().GetCode() != typev3.StatusCode_TooManyRequests || !retry ||
		!strings.Contains(string(resp.GetBody()), `"category":"rate_limited"`) {
		t.Fatalf("refusal: %v", resp)
	}
	if v := get("a2", "example.com"); !v.Allow {
		t.Fatalf("another actor of the atespace: %+v", v)
	}
	now = now.Add(time.Second)
	if v := get("a1", "example.com"); !v.Allow {
		t.Fatalf("a second later: %+v", v)
	}
}

// TestGAP0635RateLimitsConfig: 0 is the default, a negative or huge rate is
// refused, and the key parses from the callout file.
func TestGAP0635RateLimitsConfig(t *testing.T) {
	c, err := ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	if c.RateLimits.PerActorRPS != DefaultEgressPerActorRPS {
		t.Fatalf("default per_actor_rps %v", c.RateLimits.PerActorRPS)
	}
	c, err = ParseConfig([]byte(testConfig + "\nrate_limits:\n  per_actor_rps: 50\n"))
	if err != nil || c.RateLimits.PerActorRPS != 50 {
		t.Fatalf("per_actor_rps 50: %v %+v", err, c.RateLimits)
	}
	for _, bad := range []string{"-1", "2000000"} {
		if _, err := ParseConfig([]byte(testConfig + "\nrate_limits:\n  per_actor_rps: " + bad + "\n")); err == nil {
			t.Fatalf("per_actor_rps %s accepted", bad)
		}
	}
}
