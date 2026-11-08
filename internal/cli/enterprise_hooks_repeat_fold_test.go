// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// A failure that lasts is printed once and counted, not printed on every
// retry: the log of a guardian that waits for an administrator stays short.
func TestGuardianRepeatFoldsPrintTheFirstFailureAndCountTheRest(t *testing.T) {
	var folds guardianRepeatFolds
	var out bytes.Buffer
	now := time.Date(2026, 11, 8, 5, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		folds.emit(&out, now.Add(time.Duration(i)*15*time.Second), "reconcile", "boom", "the same reconcile failure", "[hook-guardian] reconcile after retry failed: boom\n")
		folds.emit(&out, now.Add(time.Duration(i)*15*time.Second), "retry", "retry", "the repair retry", "[hook-guardian] repair incomplete; retrying in 15s\n")
	}
	if got := strings.Count(out.String(), "\n"); got != 2 {
		t.Fatalf("20 identical failures and retries printed %d lines, want the 2 first ones:\n%s", got, out.String())
	}
	folds.reset(&out)
	for _, want := range []string{
		"[hook-guardian] the same reconcile failure repeated 19 more times\n",
		"[hook-guardian] the repair retry repeated 19 more times\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("the reset did not print %q:\n%s", want, out.String())
		}
	}
	// After a pass that succeeded, the same failure shows again.
	before := out.Len()
	folds.emit(&out, now.Add(time.Hour), "reconcile", "boom", "the same reconcile failure", "[hook-guardian] reconcile after retry failed: boom\n")
	if !strings.HasSuffix(out.String()[before:], "failed: boom\n") || strings.Contains(out.String()[before:], "repeated") {
		t.Fatalf("the failure after a reset was folded: %q", out.String()[before:])
	}
}

func TestGuardianRepeatFoldsShowAChangedFailureAndRefreshALongOne(t *testing.T) {
	var folds guardianRepeatFolds
	var out bytes.Buffer
	now := time.Date(2026, 11, 8, 5, 0, 0, 0, time.UTC)
	emit := func(at time.Time, key string) {
		folds.emit(&out, at, "reconcile", key, "the same reconcile failure", "[hook-guardian] reconcile failed: "+key+"\n")
	}
	emit(now, "first")
	emit(now.Add(time.Minute), "first")
	emit(now.Add(2*time.Minute), "first")
	emit(now.Add(3*time.Minute), "second")
	want := "[hook-guardian] reconcile failed: first\n" +
		"[hook-guardian] the same reconcile failure repeated 2 more times\n" +
		"[hook-guardian] reconcile failed: second\n"
	if out.String() != want {
		t.Fatalf("a changed failure:\n got %q\nwant %q", out.String(), want)
	}
	out.Reset()
	emit(now.Add(4*time.Minute), "second")
	emit(now.Add(3*time.Minute+guardianRepeatRefresh), "second")
	want = "[hook-guardian] the same reconcile failure repeated 1 more times\n[hook-guardian] reconcile failed: second\n"
	if out.String() != want {
		t.Fatalf("a failure that lasts past the refresh:\n got %q\nwant %q", out.String(), want)
	}
}
