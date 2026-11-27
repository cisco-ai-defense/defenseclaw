// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// argsMemoMin is the size of tool arguments from which the answers of
	// their readers are remembered. About twenty proofs of one call each
	// read the command field of the same arguments; for an 889 KB patch
	// every read was a full JSON decode (GAP-1040), and for the 1 MiB
	// here-document of GAP-0299 the gateway's own readers decoded the
	// arguments about a dozen times per call. Smaller arguments are decoded
	// each time, as before.
	argsMemoMin = 64 << 10
	// argsMemoCommandFieldMin is argsMemoMin for the command field
	// (argsTopLevelCommandField): a sandbox hook reads the command field of
	// one 8 KB call some hundred times, 1.5 ms a hook, so its answer is
	// remembered from a few hundred bytes (substrate-1 GAP-1028).
	argsMemoCommandFieldMin = 256
	// argsMemoMax bounds the arguments remembered.
	argsMemoMax = 4 << 20
	// argsMemoEntries bounds how many arguments are remembered: the call,
	// its twins and the hooks that run at the same time (substrate-1
	// GAP-1028).
	argsMemoEntries = 8
	// argsMemoLife is how long an answer is kept: one hook call, with room
	// for a retry.
	argsMemoLife = 30 * time.Second
)

// argsReader names a pure reader of tool arguments whose answer is kept.
type argsReader uint8

const (
	argsTopLevelCommandField argsReader = iota // decodeTrustedTopLevelCommandField
	argsRawShellCommand                        // decodeAgentHookConfigRawShellCommand
	argsWindowsCommand                         // decodeWindowsArgsCommand
	argsReaders
)

type argsMemoEntry struct {
	raw     string // a private copy, so a later edit of the caller bytes never matches
	answers [argsReaders]any
	at      time.Time
}

var argsMemo struct {
	sync.Mutex
	entries []*argsMemoEntry
}

// memoArgs answers read() for the reader and the argument text raw,
// remembering the answer for large arguments a short time. read must be a
// pure function of those bytes with an immutable answer (strings and flags):
// every caller of the same bytes gets that same value. The bytes are compared
// in full, and all readers of one argument text share one kept copy of it.
func memoArgs[T any](reader argsReader, raw string, read func() T) T {
	return memoArgsMatch(reader, len(raw), func(kept string) bool { return kept == raw },
		func() string { return strings.Clone(raw) }, read)
}

// memoArgsBytes is memoArgs for arguments held as bytes; they are copied
// only when kept.
func memoArgsBytes[T any](reader argsReader, raw []byte, read func() T) T {
	return memoArgsMatch(reader, len(raw), func(kept string) bool { return kept == string(raw) },
		func() string { return string(raw) }, read)
}

func memoArgsMatch[T any](reader argsReader, size int, match func(string) bool, keep func() string, read func() T) T {
	low := argsMemoMin
	if reader == argsTopLevelCommandField {
		low = argsMemoCommandFieldMin
	}
	if size < low || size > argsMemoMax {
		return read()
	}
	now := time.Now()
	argsMemo.Lock()
	kept := argsMemo.entries[:0]
	var hit *argsMemoEntry
	for _, entry := range argsMemo.entries {
		if now.Sub(entry.at) < argsMemoLife {
			kept = append(kept, entry)
			if hit == nil && len(entry.raw) == size && match(entry.raw) {
				hit = entry
			}
		}
	}
	clear(argsMemo.entries[len(kept):])
	argsMemo.entries = kept
	if hit != nil {
		if answer, ok := hit.answers[reader].(T); ok {
			argsMemo.Unlock()
			return answer
		}
	}
	argsMemo.Unlock()
	answer := read()
	argsMemo.Lock()
	defer argsMemo.Unlock()
	if hit != nil && slices.Contains(argsMemo.entries, hit) {
		hit.answers[reader] = answer
		return answer
	}
	entry := &argsMemoEntry{raw: keep(), at: time.Now()}
	entry.answers[reader] = answer
	if n := len(argsMemo.entries); n >= argsMemoEntries {
		copy(argsMemo.entries, argsMemo.entries[1:])
		argsMemo.entries[n-1] = nil
		argsMemo.entries = argsMemo.entries[:n-1]
	}
	argsMemo.entries = append(argsMemo.entries, entry)
	return answer
}

type trustedCommandFieldAnswer struct {
	command      string
	found, valid bool
}

// trustedTopLevelCommandField is decodeTrustedTopLevelCommandField with the
// answer for large arguments remembered for a short time.
func trustedTopLevelCommandField(raw json.RawMessage) (string, bool, bool) {
	answer := memoArgsBytes(argsTopLevelCommandField, raw, func() trustedCommandFieldAnswer {
		command, found, valid := decodeTrustedTopLevelCommandField(raw)
		return trustedCommandFieldAnswer{command, found, valid}
	})
	return answer.command, answer.found, answer.valid
}
