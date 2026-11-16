// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
)

// The path rules and the semantic path proofs read the opened path of every
// path fact (windowsOpenedPath), each of them again, and on a Windows host
// each reading asked the file system for the long names of the path
// (GetLongPathName, and its folders for a file about to be created). A call
// with 254 operands asked it some tens of thousands of times: about 80
// percent of the evaluation on a hosted Windows runner, 3.3 to 3.5 s a call,
// close to the hook deadline (GAP-1075). One evaluation now asks once per
// spelling and every reader of that evaluation gets the same answer, as the
// hook path readers already do within an evaluation (hookpaths.TargetMemo).
// Nothing is kept past the evaluation: each call asks the file system again.

// openedPathScopeKey marks a context whose evaluation holds the scope, so a
// nested dispatch of the same call opens none.
type openedPathScopeKey struct{}

// openedPaths are the long names of the one evaluation in progress. They are
// kept only while that evaluation is the only one open: when a second one
// begins, no answer is kept or read again until every evaluation has ended,
// so no evaluation reads an answer another one asked for. generation tells
// the scopes apart, so an answer asked for in one scope is never kept in a
// later one.
var openedPaths struct {
	mu         sync.Mutex
	open       int
	shared     bool
	generation uint64
	answers    map[openedPathKey]string
}

type openedPathKey struct {
	path     string
	verbatim bool
}

// maxOpenedPathAnswers bounds the answers of one evaluation; past it the
// file system is asked as before.
const maxOpenedPathAnswers = 1 << 14

// withOpenedPathScope opens the scope of one evaluation on a Windows host and
// returns its end. A context that already holds one, and any other host,
// opens none.
func withOpenedPathScope(ctx context.Context) (context.Context, func()) {
	if !windowsPathHost || ctx.Value(openedPathScopeKey{}) != nil {
		return ctx, func() {}
	}
	openedPaths.mu.Lock()
	openedPaths.open++
	openedPaths.generation++
	openedPaths.answers = nil
	openedPaths.shared = openedPaths.open > 1
	openedPaths.mu.Unlock()
	return context.WithValue(ctx, openedPathScopeKey{}, true), func() {
		openedPaths.mu.Lock()
		openedPaths.open--
		if openedPaths.open == 0 {
			openedPaths.shared = false
		}
		openedPaths.answers = nil
		openedPaths.mu.Unlock()
	}
}

// expandShortNamesInEvaluation is expandWindowsShortNames, answered once per
// spelling within the sole evaluation in progress. A failure is not kept: the
// next reader asks again, as before.
func expandShortNamesInEvaluation(path string, verbatim bool) (string, error) {
	key := openedPathKey{path: path, verbatim: verbatim}
	openedPaths.mu.Lock()
	sole := openedPaths.open == 1 && !openedPaths.shared
	generation := openedPaths.generation
	if sole {
		if long, ok := openedPaths.answers[key]; ok {
			openedPaths.mu.Unlock()
			return long, nil
		}
	}
	openedPaths.mu.Unlock()
	long, err := expandWindowsShortNames(path, verbatim)
	if !sole || err != nil {
		return long, err
	}
	openedPaths.mu.Lock()
	if openedPaths.open == 1 && !openedPaths.shared && openedPaths.generation == generation &&
		len(openedPaths.answers) < maxOpenedPathAnswers {
		if openedPaths.answers == nil {
			openedPaths.answers = make(map[openedPathKey]string)
		}
		openedPaths.answers[key] = long
	}
	openedPaths.mu.Unlock()
	return long, nil
}
