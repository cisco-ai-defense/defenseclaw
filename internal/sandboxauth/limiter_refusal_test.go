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

//go:build !windows

package sandboxauth

import (
	"errors"
	"testing"
)

// A refusal carries the limit that was in force for the binding and bucket it
// came from, so what a caller tells the user is the number the limiter
// applied: the binding's override, the telemetry bucket, a shared cap.
func TestLimiterRefusalCarriesTheLimitInForce(t *testing.T) {
	clock := newTestClock()
	l := NewLimiter(LimiterConfig{HookRPS: 2, HookBurst: 3, OTLPRPS: 0.5, OTLPBurst: 1, MaxInFlight: 100, OTLPMaxInFlight: 1, OTLPMaxInFlightTotal: 5, Now: clock.Now})
	plain := Binding{ID: "sb_plain"}
	custom := Binding{ID: "sb_custom", RateLimit: RateLimit{RequestsPerSecond: 7, Burst: 1}}
	want := func(t *testing.T, err error, kind error, limit Limit, rps float64, burst, maxIn int) {
		t.Helper()
		var got *LimitError
		if !errors.As(err, &got) || !errors.Is(err, kind) || got.Limit != limit || got.RPS != rps || got.Burst != burst || got.MaxInFlight != maxIn {
			t.Fatalf("refusal = %#v, want %v limit %d rate %v burst %d in flight %d", err, kind, limit, rps, burst, maxIn)
		}
	}
	for i := 0; i < 3; i++ {
		admit(t, l, plain, RouteHook)
	}
	_, err := l.Acquire(plain, RouteHook)
	want(t, err, ErrRateLimited, LimitHook, 2, 3, 0)

	capped := Binding{ID: "sb_capped", RateLimit: RateLimit{MaxInFlight: 1}}
	if _, err := l.Acquire(capped, RouteHook); err != nil {
		t.Fatal(err)
	}
	_, err = l.Acquire(capped, RouteHook)
	want(t, err, ErrTooManyInFlight, LimitHook, 0, 0, 1)

	if _, err := l.Acquire(plain, RouteOTLP); err != nil {
		t.Fatal(err)
	}
	_, err = l.Acquire(plain, RouteOTLP)
	want(t, err, ErrTooManyInFlight, LimitTelemetry, 0, 0, 1)

	_, err = l.AcquireReceipt(custom)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ChargeHookBody(custom, true); err == nil {
		t.Fatal("a second receipt on a burst of 1 was admitted")
	} else {
		want(t, err, ErrRateLimited, LimitReceipt, 7, 1, 0)
	}
}
