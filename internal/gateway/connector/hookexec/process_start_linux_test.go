// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"math"
	"testing"
	"time"
)

func TestParseProcStatStartTicks(t *testing.T) {
	// The command name may hold spaces and parentheses.
	stat := "4242 (a b) (c)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 19 20\n"
	if got, ok := parseProcStatStartTicks(stat); !ok || got != 987654 {
		t.Fatalf("parseProcStatStartTicks = %d, %v; want 987654", got, ok)
	}
	for _, bad := range []string{"", "4242 no-paren S 1", "4242 (x) S 1 2 3", "4242 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 -5"} {
		if _, ok := parseProcStatStartTicks(bad); ok {
			t.Errorf("parseProcStatStartTicks(%q) accepted a malformed line", bad)
		}
	}
}

// GAP-0648 review F1: the age of the process start holds at any uptime.
// ticks * time.Second overflowed past about 1067 days of uptime, so on such
// a host every hook start was years old and every bounded call was blocked
// at once. A start after the boot clock's now is not known.
func TestProcStartAgeHoldsAtAnyUptime(t *testing.T) {
	const day = 24 * time.Hour
	tick := time.Second / linuxClockTicks
	startedAt := func(sinceBoot, age time.Duration) uint64 { return uint64((sinceBoot - age) / tick) }
	for _, test := range []struct {
		name      string
		ticks     uint64
		sinceBoot time.Duration
		want      time.Duration
		ok        bool
	}{
		{"1000 days up", startedAt(1000*day, 500*time.Millisecond), 1000 * day, 500 * time.Millisecond, true},
		{"1068 days up", startedAt(1068*day, 500*time.Millisecond), 1068 * day, 500 * time.Millisecond, true},
		{"1500 days up", startedAt(1500*day, 500*time.Millisecond), 1500 * day, 500 * time.Millisecond, true},
		{"1500 days up, started at boot", 0, 1500 * day, 1500 * day, true},
		{"started now", startedAt(time.Hour, 0), time.Hour, 0, true},
		{"started after the boot clock's now", startedAt(time.Hour, -time.Second), time.Hour, 0, false},
		{"ticks past any clock", math.MaxUint64, 1500 * day, 0, false},
		{"negative boot clock", 0, -time.Second, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := procStartAge(test.ticks, test.sinceBoot)
			if ok != test.ok || got != test.want {
				t.Fatalf("procStartAge(%d, %s) = %s, %t; want %s, %t", test.ticks, test.sinceBoot, got, ok, test.want, test.ok)
			}
		})
	}
}
