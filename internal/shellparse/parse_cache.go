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
	at   time.Time
}

var parseCache struct {
	sync.Mutex
	entries []parseCacheEntry
}

// cachedParse returns a private copy of the kept tree of command.
func cachedParse(key parseCacheKey) (file *syntax.File, ok, hit bool) {
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
			return cloneFile(entry.file), entry.ok, true
		}
	}
	return nil, false, false
}

// storeParse keeps a private copy of file; the caller goes on to use file.
func storeParse(key parseCacheKey, file *syntax.File, ok bool) {
	entry := parseCacheEntry{key: key, file: cloneFile(file), ok: ok, at: time.Now()}
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
	deep    bool
	set     bool
}

func tooDeepLarge(command string) bool {
	tooDeepMemo.Lock()
	if tooDeepMemo.set && tooDeepMemo.command == command {
		deep := tooDeepMemo.deep
		tooDeepMemo.Unlock()
		return deep
	}
	tooDeepMemo.Unlock()
	deep := tooDeepScan(command)
	tooDeepMemo.Lock()
	tooDeepMemo.command, tooDeepMemo.deep, tooDeepMemo.set = command, deep, true
	tooDeepMemo.Unlock()
	return deep
}

// cloneFile returns a copy of file that shares no node with it. The syntax
// nodes hold pointers, slices and interfaces of nodes, strings, and positions
// (a struct of unexported integers, copied by value); nothing else.
func cloneFile(file *syntax.File) *syntax.File {
	if file == nil {
		return nil
	}
	return cloneValue(reflect.ValueOf(file)).Interface().(*syntax.File)
}

func cloneValue(src reflect.Value) reflect.Value {
	switch src.Kind() {
	case reflect.Pointer:
		if src.IsNil() {
			return src
		}
		dst := reflect.New(src.Type().Elem())
		dst.Elem().Set(cloneValue(src.Elem()))
		return dst
	case reflect.Interface:
		if src.IsNil() {
			return src
		}
		dst := reflect.New(src.Type()).Elem()
		dst.Set(cloneValue(src.Elem()))
		return dst
	case reflect.Slice:
		if src.IsNil() {
			return src
		}
		dst := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
		for i := range src.Len() {
			dst.Index(i).Set(cloneValue(src.Index(i)))
		}
		return dst
	case reflect.Struct:
		dst := reflect.New(src.Type()).Elem()
		dst.Set(src)
		for i := range src.NumField() {
			if src.Type().Field(i).IsExported() {
				dst.Field(i).Set(cloneValue(src.Field(i)))
			}
		}
		return dst
	default:
		return src
	}
}
