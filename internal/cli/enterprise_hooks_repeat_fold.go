// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"runtime"
	"sort"
	"sync"
	"time"
)

// guardianRepeatRefresh is how long a failure line is folded before it is
// printed again, so a failure that lasts for days still shows in the log.
const guardianRepeatRefresh = 15 * time.Minute

// enterpriseHookRepeatFolds is the one fold state of the guardian process: the
// watch loop and the reconcile run both write to it.
var enterpriseHookRepeatFolds guardianRepeatFolds

// enterpriseHookLinkCauseFolds folds the cause of a typed link failure. A pass
// that fails only on a link succeeds, which resets enterpriseHookRepeatFolds,
// so the cause has its own state: it is printed again only when it changes or
// after guardianRepeatRefresh.
var enterpriseHookLinkCauseFolds guardianRepeatFolds

// enterpriseHookFoldRepeats reports whether this guardian folds repeated
// lines: the standalone Windows guardian only. Secure Client and the other
// platforms log every line, as they always did. A seam for tests.
var enterpriseHookFoldRepeats = func() bool {
	return runtime.GOOS == "windows" && cfg != nil && cfg.StandaloneEnterprise()
}

// guardianRepeatFolds keeps the hook guardian log from repeating one failure
// on every retry. While an administrator action is needed (a link at a vendor
// folder, for example) the guardian retries at its backoff cap and each pass
// failed with the same text: the first line is printed, the identical lines
// that follow are counted, and the count is printed once when the failure
// changes, when a pass succeeds (reset), or every guardianRepeatRefresh.
type guardianRepeatFolds struct {
	mu     sync.Mutex
	states map[string]*guardianRepeatState
}

type guardianRepeatState struct {
	key     string
	note    string
	printed time.Time
	folded  int
}

// emit prints line (which ends in a newline) unless key is the key last
// printed for kind within guardianRepeatRefresh, in which case it only counts
// it. note names what is counted in the summary line.
func (f *guardianRepeatFolds) emit(w io.Writer, now time.Time, kind, key, note, line string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states == nil {
		f.states = map[string]*guardianRepeatState{}
	}
	if state := f.states[kind]; state != nil && state.key == key && now.Sub(state.printed) < guardianRepeatRefresh {
		state.folded++
		return
	}
	f.flushLocked(w, kind)
	fmt.Fprint(w, line)
	f.states[kind] = &guardianRepeatState{key: key, note: note, printed: now}
}

// reset prints the pending counts and forgets every line: the next failure,
// after a pass that succeeded, is printed again.
func (f *guardianRepeatFolds) reset(w io.Writer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kinds := make([]string, 0, len(f.states))
	for kind := range f.states {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		f.flushLocked(w, kind)
	}
	f.states = nil
}

func (f *guardianRepeatFolds) flushLocked(w io.Writer, kind string) {
	if state := f.states[kind]; state != nil && state.folded > 0 {
		fmt.Fprintf(w, "[hook-guardian] %s repeated %d more times\n", state.note, state.folded)
		state.folded = 0
	}
}
