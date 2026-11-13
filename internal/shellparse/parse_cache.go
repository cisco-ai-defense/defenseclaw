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
	// largeCommandMin is the size from which a command is cached.
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

// cloneTask copies src into dst; with assign set, it only stores src, a copy
// that has been completed, into dst.
type cloneTask struct {
	dst, src reflect.Value
	assign   bool
}

// cloneFile returns a copy of file that shares no node with it. The syntax
// nodes hold pointers, slices and interfaces of nodes, strings, and
// positions (a struct of unexported integers, copied by value); nothing
// else. The copy walks the tree with an explicit stack, not recursion, so
// the depth of the tree costs heap, not goroutine stack: a stack overflow
// is a fatal error no recover catches (GAP-0255). The size of the tree is
// bounded by the reading budget (BudgetExceeded) before a command is
// parsed.
func cloneFile(file *syntax.File) *syntax.File {
	if file == nil {
		return nil
	}
	root := reflect.New(reflect.TypeFor[*syntax.File]()).Elem()
	stack := []cloneTask{{dst: root, src: reflect.ValueOf(file)}}
	for len(stack) > 0 {
		task := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		dst, src := task.dst, task.src
		if task.assign {
			dst.Set(src)
			continue
		}
		switch src.Kind() {
		case reflect.Pointer:
			if src.IsNil() {
				continue
			}
			copied := reflect.New(src.Type().Elem())
			dst.Set(copied)
			stack = append(stack, cloneTask{dst: copied.Elem(), src: src.Elem()})
		case reflect.Interface:
			if src.IsNil() {
				continue
			}
			held := src.Elem()
			if held.Kind() == reflect.Pointer {
				// The interface holds a pointer: store the new object now
				// and fill it where it is.
				if held.IsNil() {
					dst.Set(held)
					continue
				}
				copied := reflect.New(held.Type().Elem())
				dst.Set(copied)
				stack = append(stack, cloneTask{dst: copied.Elem(), src: held.Elem()})
				continue
			}
			// A value in the interface is copied whole before it is stored.
			copied := reflect.New(held.Type()).Elem()
			stack = append(stack, cloneTask{dst: dst, src: copied, assign: true}, cloneTask{dst: copied, src: held})
		case reflect.Slice:
			if src.IsNil() {
				continue
			}
			copied := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
			dst.Set(copied)
			for i := range src.Len() {
				stack = append(stack, cloneTask{dst: copied.Index(i), src: src.Index(i)})
			}
		case reflect.Struct:
			dst.Set(src)
			for i := range src.NumField() {
				if !src.Type().Field(i).IsExported() {
					continue
				}
				switch src.Field(i).Kind() {
				case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Struct:
					stack = append(stack, cloneTask{dst: dst.Field(i), src: src.Field(i)})
				}
			}
		default:
			dst.Set(src)
		}
	}
	return root.Interface().(*syntax.File)
}
