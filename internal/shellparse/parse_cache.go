// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"reflect"
	"sync"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

// A call of hundreds of kilobytes (an apply_patch here-document) is read by
// about twenty proofs, each of which parses the same command again: the
// parser reads a quoted here-document one rune at a time, so every parse of an
// 889 KB patch cost tens of milliseconds and the repeats took most of the
// window of the hook (GAP-1040). Parse and ParseWithComments therefore keep
// the tree of a large command for a short time and hand every caller its own
// copy, because callers rewrite trees in place. A command under
// largeCommandMin is parsed as before and never enters the cache.
const (
	// largeCommandMin is the size from which a command is cached (and its
	// nesting bound remembered).
	largeCommandMin = 64 << 10
	// largeCommandMax bounds the commands kept; a larger one is parsed each
	// time.
	largeCommandMax = 4 << 20
	// parseCacheEntries bounds how many large commands are kept.
	parseCacheEntries = 4
	// parseCacheLife is how long a kept command stays: one hook call, with
	// room for a retry.
	parseCacheLife = 30 * time.Second
)

type parseCacheKey struct {
	command  string
	comments bool
}

type parseCacheEntry struct {
	key  parseCacheKey
	file *syntax.File // the tree as parsed, never handed out
	ok   bool
	over bool // parsed, but past MaxParsedNodes (file is nil)
	at   time.Time
}

var parseCache struct {
	sync.Mutex
	entries []parseCacheEntry
}

// cachedParse returns a private copy of the kept tree of command.
func cachedParse(key parseCacheKey) (file *syntax.File, ok, over, hit bool) {
	parseCache.Lock()
	defer parseCache.Unlock()
	now := time.Now()
	kept := parseCache.entries[:0]
	for _, entry := range parseCache.entries {
		if now.Sub(entry.at) < parseCacheLife {
			kept = append(kept, entry)
		}
	}
	parseCache.entries = kept
	for _, entry := range kept {
		if entry.key == key {
			if copied, cloned := cloneFile(entry.file); cloned {
				return copied, entry.ok, entry.over, true
			}
			return nil, false, false, false
		}
	}
	return nil, false, false, false
}

// storeParse keeps a private copy of file; the caller goes on to use file.
func storeParse(key parseCacheKey, file *syntax.File, ok, over bool) {
	kept, cloned := cloneFile(file)
	if !cloned {
		// A tree too deep to copy within the clone bound is not kept.
		return
	}
	entry := parseCacheEntry{key: key, file: kept, ok: ok, over: over, at: time.Now()}
	parseCache.Lock()
	defer parseCache.Unlock()
	if len(parseCache.entries) >= parseCacheEntries {
		parseCache.entries = append(parseCache.entries[:0], parseCache.entries[1:]...)
	}
	parseCache.entries = append(parseCache.entries, entry)
}

// tooDeepMemo remembers the nesting answer of the last large command: the
// proofs ask it for the same text on every parse and every reader.
var tooDeepMemo struct {
	sync.Mutex
	command string
	reason  string
	set     bool
}

func tooDeepRemembered(command string) string {
	tooDeepMemo.Lock()
	if tooDeepMemo.set && tooDeepMemo.command == command {
		reason := tooDeepMemo.reason
		tooDeepMemo.Unlock()
		return reason
	}
	tooDeepMemo.Unlock()
	reason, measure := tooDeepScan(command)
	if reason == "" && measure && chainTreeOver(command) {
		reason = BudgetChain
	}
	tooDeepMemo.Lock()
	tooDeepMemo.command, tooDeepMemo.reason, tooDeepMemo.set = command, reason, true
	tooDeepMemo.Unlock()
	return reason
}

// maxCloneDepth bounds the reflection depth of cloneValue (every pointer,
// interface, slice element and struct field it descends through counts
// one). A tree that passes the reading budget (MaxNestingDepth nesting and
// MaxChainOperators operators in a chain) is far below it; it is the stop
// for a tree that did not, so the copy returns an error instead of
// overflowing the goroutine stack, which is a fatal error no recover
// catches (GAP-0255: a 500 KB left-deep || list killed the gateway).
const maxCloneDepth = 1 << 17

// cloneFile returns a copy of file that shares no node with it, and false
// when the tree is deeper than maxCloneDepth. The syntax nodes hold
// pointers, slices and interfaces of nodes, strings, and positions (a
// struct of unexported integers, copied by value); nothing else.
func cloneFile(file *syntax.File) (*syntax.File, bool) {
	if file == nil {
		return nil, true
	}
	copied, ok := cloneValue(reflect.ValueOf(file), 0)
	if !ok {
		return nil, false
	}
	return copied.Interface().(*syntax.File), true
}

func cloneValue(src reflect.Value, depth int) (reflect.Value, bool) {
	if depth > maxCloneDepth {
		return reflect.Value{}, false
	}
	depth++
	switch src.Kind() {
	case reflect.Pointer:
		if src.IsNil() {
			return src, true
		}
		inner, ok := cloneValue(src.Elem(), depth)
		if !ok {
			return reflect.Value{}, false
		}
		dst := reflect.New(src.Type().Elem())
		dst.Elem().Set(inner)
		return dst, true
	case reflect.Interface:
		if src.IsNil() {
			return src, true
		}
		inner, ok := cloneValue(src.Elem(), depth)
		if !ok {
			return reflect.Value{}, false
		}
		dst := reflect.New(src.Type()).Elem()
		dst.Set(inner)
		return dst, true
	case reflect.Slice:
		if src.IsNil() {
			return src, true
		}
		dst := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
		for i := range src.Len() {
			inner, ok := cloneValue(src.Index(i), depth)
			if !ok {
				return reflect.Value{}, false
			}
			dst.Index(i).Set(inner)
		}
		return dst, true
	case reflect.Struct:
		dst := reflect.New(src.Type()).Elem()
		dst.Set(src)
		for i := range src.NumField() {
			if src.Type().Field(i).IsExported() {
				inner, ok := cloneValue(src.Field(i), depth)
				if !ok {
					return reflect.Value{}, false
				}
				dst.Field(i).Set(inner)
			}
		}
		return dst, true
	default:
		return src, true
	}
}
