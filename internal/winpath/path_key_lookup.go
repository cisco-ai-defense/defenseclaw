// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"sync"
	"time"
)

// longNameCacheMax bounds the spellings longNameLookups remembers.
const longNameCacheMax = 256

// longNameLookups runs the long-name lookups of ComparisonKey with a bound.
// The key it gives one spelling must not change while the spelling names
// one folder: the guardian keeps pending restores under it across passes,
// and the WinGet scan slot is held under it until a stuck listing returns.
// An 8.3 alias is recycled, though: once its folder is deleted, the next
// folder made with a similar name gets the same short name, and a kept long
// name would key the new folder as the deleted one (rel-1-0-6:GAP-0449).
// So every call of an expanded spelling looks it up again; an in-time answer
// replaces the kept long name, and a lookup that fails (the folder is gone
// and no other folder has the alias yet) or does not answer within the
// budget gives back the kept one. A spelling whose first lookup did not
// answer keeps the spelling itself as its key and is not looked up again,
// so stalled storage is asked once. At most one lookup per spelling runs;
// a late answer is dropped. A first lookup that fails fast (the path does
// not exist yet) is not kept, so a later call can still expand it.
type longNameLookups struct {
	mu      sync.Mutex
	known   map[string]string
	running map[string]bool
}

func newLongNameLookups() *longNameLookups {
	return &longNameLookups{known: map[string]string{}, running: map[string]bool{}}
}

// expand returns the long name of path from lookup and true, or "" and
// false when there is none or it did not answer within budget.
func (l *longNameLookups) expand(path string, budget time.Duration, lookup func(string) (string, bool)) (string, bool) {
	l.mu.Lock()
	kept, known := l.known[path]
	if known && kept == path {
		l.mu.Unlock()
		return "", false
	}
	if l.running[path] {
		// A lookup of this spelling has not returned yet; do not start a
		// second one on the same storage.
		l.mu.Unlock()
		return kept, known
	}
	l.running[path] = true
	l.mu.Unlock()

	type answer struct {
		long string
		ok   bool
	}
	answers := make(chan answer, 1)
	go func() {
		long, ok := lookup(path)
		answers <- answer{long, ok}
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case got := <-answers:
		l.mu.Lock()
		delete(l.running, path)
		if got.ok && got.long != "" {
			l.remember(path, got.long)
		}
		l.mu.Unlock()
		if got.ok && got.long != "" {
			return got.long, true
		}
		return kept, known
	case <-timer.C:
		l.mu.Lock()
		if !known {
			l.remember(path, path)
		}
		l.mu.Unlock()
		go func() {
			<-answers
			l.mu.Lock()
			delete(l.running, path)
			l.mu.Unlock()
		}()
		return kept, known
	}
}

// remember keeps key for path; the caller holds l.mu. A full cache keeps
// its entries and takes no new spelling.
func (l *longNameLookups) remember(path, key string) {
	if _, ok := l.known[path]; ok || len(l.known) < longNameCacheMax {
		l.known[path] = key
	}
}
