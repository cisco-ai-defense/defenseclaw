// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"testing"
	"time"
)

// A call inside its bound passes on its wall time, one over MaxStretch bounds
// never passes whatever the host denied it, and between the two the host's
// denial is taken off.
func TestCallWithinKeepsTheBoundWhereTheHostIsNotShort(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	for _, tc := range []struct {
		name         string
		denied, took time.Duration
		want         bool
	}{
		{"inside the bound", 0, ms(900), true},
		{"over the bound, no denial", 0, ms(1100), false},
		{"over the bound by what the host denied", ms(200), ms(1100), true},
		{"over the bound by more than the host denied", ms(50), ms(1100), false},
		{"over MaxStretch bounds, whatever was denied", ms(3000), time.Duration(float64(time.Second) * (MaxStretch + 0.5)), false},
	} {
		if got := (Call{denied: tc.denied}).Within(tc.took, time.Second); got != tc.want {
			t.Errorf("%s: Within = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Only a busy thread names the host: a sleeper reads nothing however long the
// host kept others waiting, and a thread that began or ended inside the
// interval is not read. A busy thread kept off the CPU for a quarter of the
// interval starves the window; less does not.
func TestStarvedBetweenNamesOnlyTheWaitOfBusyThreads(t *testing.T) {
	const wall = time.Second
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	for _, tc := range []struct {
		name          string
		before, after map[int]threadTimes
		want          bool
	}{
		{"idle process", map[int]threadTimes{1: {}}, map[int]threadTimes{1: {run: ms(1)}}, false},
		{"a sleeper beside a starved host", map[int]threadTimes{1: {}}, map[int]threadTimes{1: {run: ms(2), wait: ms(30)}}, false},
		{"one thread without the CPU for 600 ms", map[int]threadTimes{1: {}}, map[int]threadTimes{1: {run: ms(300), wait: ms(600)}}, true},
		{"one thread without the CPU for 300 ms", map[int]threadTimes{1: {}}, map[int]threadTimes{1: {run: ms(600), wait: ms(300)}}, true},
		{"one thread without the CPU for 200 ms", map[int]threadTimes{1: {}}, map[int]threadTimes{1: {run: ms(700), wait: ms(200)}}, false},
		{"one starved thread of two", map[int]threadTimes{1: {}, 2: {}},
			map[int]threadTimes{1: {run: ms(900), wait: ms(50)}, 2: {run: ms(200), wait: ms(700)}}, true},
		{"a thread that began inside the interval", map[int]threadTimes{1: {}}, map[int]threadTimes{2: {run: ms(300), wait: ms(600)}}, false},
		{"a counter that went back", map[int]threadTimes{1: {run: ms(900)}}, map[int]threadTimes{1: {run: ms(100), wait: ms(500)}}, false},
	} {
		if got := starvedBetween(tc.before, tc.after, wall); got != tc.want {
			t.Errorf("%s: starvedBetween = %v, want %v", tc.name, got, tc.want)
		}
	}
	if starvedBetween(map[int]threadTimes{1: {}}, map[int]threadTimes{1: {wait: time.Second}}, 0) {
		t.Error("an empty interval was starved")
	}
}
