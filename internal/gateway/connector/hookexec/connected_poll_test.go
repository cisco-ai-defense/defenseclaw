// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"testing"
	"time"
)

func TestNextConnectedPollPauseBacksOffToTheOldTick(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 16, 20, 20, 20}
	attempt := 0
	for i, ms := range want {
		if got := nextConnectedPollPause(&attempt); got != ms*time.Millisecond {
			t.Fatalf("pause %d = %v, want %v", i, got, ms*time.Millisecond)
		}
	}
	if attempt != len(want) {
		t.Fatalf("attempts counted %d, want %d", attempt, len(want))
	}
}
