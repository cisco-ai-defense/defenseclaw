// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package textlower gives one shared lower-cased copy of a large text. Many
// readers of one hook call each lower-cased the whole command to look for a
// name in it; for the 1 MiB here-document of GAP-0299 that was a dozen 1 MiB
// copies per call. Lower is strings.ToLower, remembered for large texts a
// short time.
package textlower

import (
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/workcount"
)

const (
	// memoMin is the size from which a lower-cased copy is kept.
	memoMin = workcount.Large
	// memoMax bounds the texts kept.
	memoMax = 4 << 20
	// memoEntries bounds how many texts are kept.
	memoEntries = 4
	// memoLife is how long a copy is kept: one hook call, with room for a
	// retry.
	memoLife = 30 * time.Second
)

type entry struct {
	text, lower string
	at          time.Time
}

var memo struct {
	sync.Mutex
	entries []entry
}

// Lower returns strings.ToLower(text). A text of 64 KiB or more is lowered
// once and the copy is handed to every caller of the same text for a short
// time; strings are immutable, so the copy is shared safely.
func Lower(text string) string {
	if len(text) < memoMin || len(text) > memoMax {
		return strings.ToLower(text)
	}
	now := time.Now()
	memo.Lock()
	kept := memo.entries[:0]
	for _, e := range memo.entries {
		if now.Sub(e.at) < memoLife {
			kept = append(kept, e)
		}
	}
	clear(memo.entries[len(kept):])
	memo.entries = kept
	for _, e := range kept {
		if e.text == text {
			memo.Unlock()
			return e.lower
		}
	}
	memo.Unlock()
	workcount.Add(workcount.TextLower)
	lower := strings.ToLower(text)
	memo.Lock()
	defer memo.Unlock()
	if n := len(memo.entries); n >= memoEntries {
		copy(memo.entries, memo.entries[1:])
		memo.entries[n-1] = entry{}
		memo.entries = memo.entries[:n-1]
	}
	memo.entries = append(memo.entries, entry{text: text, lower: lower, at: time.Now()})
	return lower
}
