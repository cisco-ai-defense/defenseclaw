// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// GAP-0050: the LocalSystem gateway checks several paths of every managed
// hook call against the Windows profile roots. The root names are read each
// time; their resolution (a file open per root) is reused for unchanged
// names for a few seconds, and redone at once when the names change, after
// the reuse window, or after a failed resolution.
func TestProfileRootResolutionIsReusedOnlyForTheSameRootsBriefly(t *testing.T) {
	var cache profileRootResolution
	opened := 0
	resolve := func(root string) (string, error) {
		opened++
		return `D:\redirected` + root[2:], nil
	}
	start := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	roots := []string{`C:\Users`, `C:\Users\alice`}
	want := []string{`C:\Users`, `D:\redirected\Users`, `C:\Users\alice`, `D:\redirected\Users\alice`}
	for i := range 60 {
		got, err := cache.resolve(roots, start.Add(time.Duration(i)*50*time.Millisecond), resolve)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("check %d: roots = %v, %v; want %v", i, got, err, want)
		}
	}
	if opened != len(roots) {
		t.Fatalf("60 checks of the same roots opened %d roots, want %d", opened, len(roots))
	}
	got, _ := cache.resolve(roots, start, resolve)
	got[1] = "edited"
	if again, _ := cache.resolve(roots, start, resolve); again[1] != want[1] {
		t.Fatal("a caller edit changed the kept resolution")
	}

	added := append(slices.Clone(roots), `C:\Users\bob`)
	if got, _ := cache.resolve(added, start.Add(time.Second), resolve); len(got) != 6 || opened != 5 {
		t.Fatalf("a new profile root was not resolved at once: %v (opened %d)", got, opened)
	}
	if _, _ = cache.resolve(added, start.Add(time.Second+profileRootResolutionReuse), resolve); opened != 8 {
		t.Fatalf("the resolution was reused past %v (opened %d)", profileRootResolutionReuse, opened)
	}
	if _, _ = cache.resolve(added, start, resolve); opened != 11 {
		t.Fatalf("a clock that went back reused the resolution (opened %d)", opened)
	}

	failing := errors.New("open failed")
	if _, err := cache.resolve(roots, start.Add(time.Minute), func(string) (string, error) { return "", failing }); !errors.Is(err, failing) {
		t.Fatalf("failed resolution = %v, want %v", err, failing)
	}
	if _, err := cache.resolve(roots, start.Add(time.Minute), resolve); err != nil || opened != 13 {
		t.Fatalf("a failed resolution was kept: %v (opened %d)", err, opened)
	}
}
