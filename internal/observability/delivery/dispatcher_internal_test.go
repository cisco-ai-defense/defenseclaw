// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"fmt"
	"testing"
	"time"
)

func TestHealthVocabularyHasExactlySevenStates(t *testing.T) {
	states := []HealthState{
		HealthDisabled, HealthInitializing, HealthHealthy, HealthDegraded,
		HealthFailing, HealthDraining, HealthStopped,
	}
	if got, want := fmt.Sprint(states), "[disabled initializing healthy degraded failing draining stopped]"; got != want {
		t.Fatalf("states=%s want=%s", got, want)
	}
}

func TestBoundedBackoffExponentAndJitterClamp(t *testing.T) {
	policy := RetryPolicy{
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     25 * time.Millisecond,
		Jitter:         func(delay time.Duration, _ int) time.Duration { return delay },
	}
	for _, test := range []struct {
		attempt int
		want    time.Duration
	}{{1, 10 * time.Millisecond}, {2, 20 * time.Millisecond}, {3, 25 * time.Millisecond}, {31, 25 * time.Millisecond}} {
		if got := boundedBackoff(policy, test.attempt); got != test.want {
			t.Fatalf("attempt %d delay=%s want=%s", test.attempt, got, test.want)
		}
	}
	policy.Jitter = func(time.Duration, int) time.Duration { return time.Hour }
	if got := boundedBackoff(policy, 1); got != policy.MaxBackoff {
		t.Fatalf("large jitter=%s", got)
	}
	policy.Jitter = func(time.Duration, int) time.Duration { return -time.Second }
	if got := boundedBackoff(policy, 1); got != 0 {
		t.Fatalf("negative jitter=%s", got)
	}
	policy.Jitter = func(time.Duration, int) time.Duration { panic("jitter panic") }
	if got := boundedBackoff(policy, 1); got != policy.InitialBackoff {
		t.Fatalf("panic fallback=%s", got)
	}
}
