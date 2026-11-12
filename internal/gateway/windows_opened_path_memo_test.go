// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"testing"
)

// One evaluation asks the file system once for the long names of a spelling,
// however many readers ask for its opened path, and every reader gets the
// answer of the file system. The next evaluation asks again and sees a name
// that changed in between; while two evaluations overlap, nothing is kept,
// and a failure is asked again (GAP-1075).
func TestOpenedPathLongNamesAreAskedOncePerEvaluation(t *testing.T) {
	oldExpand, oldHost := expandWindowsShortNames, windowsPathHost
	t.Cleanup(func() { expandWindowsShortNames, windowsPathHost = oldExpand, oldHost })
	windowsPathHost = true
	asks := 0
	long := "C:/Users/alice/.netrc"
	var failure error
	expandWindowsShortNames = func(path string, _ bool) (string, error) {
		asks++
		if failure != nil {
			return path, failure
		}
		if path == "C:/Users/ALICE~1/NETRC~1" {
			return long, nil
		}
		return path, nil
	}
	read := func() string {
		opened, ok, err := windowsOpenedPath(`C:\Users\ALICE~1\NETRC~1`, false)
		if !ok || err != nil {
			t.Fatalf("opened path: ok=%v err=%v", ok, err)
		}
		return opened
	}
	evaluate := func(reads int) (answers []string) {
		_, end := withOpenedPathScope(context.Background())
		defer end()
		for range reads {
			answers = append(answers, read())
		}
		return answers
	}

	if got := evaluate(5); asks != 1 || got[0] != long || got[4] != long {
		t.Fatalf("one evaluation: %d asks, answers %q; want 1 ask and %q", asks, got, long)
	}
	long, asks = "C:/Users/alice/renamed", 0
	if got := evaluate(2); asks != 1 || got[1] != long {
		t.Fatalf("next evaluation: %d asks, answers %q; want a fresh ask and %q", asks, got, long)
	}

	asks = 0
	ctx, endFirst := withOpenedPathScope(context.Background())
	if nested, endNested := withOpenedPathScope(ctx); nested != ctx {
		t.Fatal("a nested dispatch of the same evaluation opened a second scope")
	} else {
		endNested()
	}
	_, endSecond := withOpenedPathScope(context.Background())
	read()
	read()
	endSecond()
	read()
	endFirst()
	if asks != 3 {
		t.Fatalf("overlapping evaluations: %d asks, want 3 (nothing kept while two are open)", asks)
	}

	asks, failure = 0, errors.New("folder cannot be listed")
	_, end := withOpenedPathScope(context.Background())
	_, _, firstErr := windowsOpenedPath(`C:\Users\ALICE~1\NETRC~1`, false)
	_, _, secondErr := windowsOpenedPath(`C:\Users\ALICE~1\NETRC~1`, false)
	end()
	if asks != 2 || firstErr == nil || secondErr == nil {
		t.Fatalf("failure: %d asks (errors %v, %v), want 2 asks that both fail", asks, firstErr, secondErr)
	}

	asks, failure = 0, nil
	read()
	read()
	if asks != 2 {
		t.Fatalf("outside an evaluation: %d asks, want 2", asks)
	}
}
