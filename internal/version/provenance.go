// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package version centralises the DefenseClaw provenance quartet
// (schema_version + content_hash + generation + binary_version) that
// every observability event stamps onto itself starting in v7. The
// quartet lets downstream consumers answer three independent questions
// without a separate config fetch:
//
//  1. "Can I parse this event?"         -> SchemaVersion
//  2. "What config produced this?"      -> ContentHash
//  3. "Did config change since last?"   -> Generation (monotonic)
//  4. "What binary emitted this?"       -> BinaryVersion
//
// All four fields are read-only from caller POV: writers go through
// Current() and SetCurrent() exclusively so tests can override while
// production code stays racy-read safe via atomic.Value.
package version

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// SchemaVersion is the stable identifier for the current v7 event
// envelope. Downstream consumers that encounter an unknown value MUST
// refuse to decode type-specific payloads and fall through to a
// minimal envelope-only decode. Bumping SchemaVersion is a breaking
// change; adding a NEW optional field is not and does not bump it.
const SchemaVersion = 7

// Provenance is the four-field quartet stamped onto every v7+ event.
//
// Zero-value semantics:
//   - ContentHash == ""  -> config not yet loaded; emit as empty string.
//   - Generation  == 0   -> monotonic counter has not ticked; valid.
//   - BinaryVersion == "" -> ldflags not applied (go run / tests); fall
//     back to the debug.ReadBuildInfo module version and finally to
//     "dev" so events stay decodable.
type Provenance struct {
	SchemaVersion int    `json:"schema_version"`
	ContentHash   string `json:"content_hash"`
	Generation    uint64 `json:"generation"`
	BinaryVersion string `json:"binary_version"`
}

// binaryVersion is set by the root main package via SetBinaryVersion
// during startup. Kept package-level rather than injected through the
// Provider to avoid threading a version argument through every
// sidecar/gateway/watcher constructor.
var binaryVersion atomic.Value // string

// generation is the monotonic counter bumped on every Save() of
// config/policy. Loaded via atomic.Uint64 so concurrent Current()
// reads stay racy-free without a lock.
var generation atomic.Uint64

// contentHash holds the last Save()'d config fingerprint. Guarded by
// the same atomic.Value pattern as binaryVersion so readers see a
// consistent snapshot even when Save() is mid-write.
var contentHash atomic.Value // string

// SetBinaryVersion is called once during process startup from main()
// (both CLI and gateway) with the ldflags-injected semver. Repeated
// calls are idempotent - last writer wins, which is the expected
// behavior for hot-reload edge cases.
func SetBinaryVersion(v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		v = fallbackBuildVersion()
	}
	binaryVersion.Store(v)
}

// SetContentHash records the fingerprint of the most recent
// config/policy Save(). Callers pass any canonical byte slice (e.g.,
// the marshalled config after key-sorted JSON); this helper hashes it
// to a 64-char lowercase hex digest so the wire format is stable.
// Empty input clears the value (useful in tests).
func SetContentHash(raw []byte) {
	if len(raw) == 0 {
		contentHash.Store("")
		return
	}
	sum := sha256.Sum256(raw)
	contentHash.Store(hex.EncodeToString(sum[:]))
}

// SetContentHashCanonicalJSON is a convenience wrapper that
// canonicalizes the supplied map via key-sorted JSON before hashing.
// This guarantees two Save()s of equivalent but differently-ordered
// configs produce the same ContentHash, which is a property downstream
// dashboards rely on when computing "config churn" rates.
func SetContentHashCanonicalJSON(m map[string]any) error {
	buf, err := canonicalJSON(m)
	if err != nil {
		return err
	}
	SetContentHash(buf)
	return nil
}

// BumpGeneration increments the monotonic generation counter.
// Callers should only invoke on a successful Save() of config or
// policy - a failed Save() must not leave a stale generation bump or
// downstream churn alerts will fire spuriously.
func BumpGeneration() uint64 {
	return generation.Add(1)
}

// Current returns the current provenance quartet. Safe for concurrent
// use. Returned value is a copy - callers may not mutate it without
// risking observer confusion on the next read.
func Current() Provenance {
	h, _ := contentHash.Load().(string)
	v, _ := binaryVersion.Load().(string)
	if v == "" {
		v = fallbackBuildVersion()
	}
	return Provenance{
		SchemaVersion: SchemaVersion,
		ContentHash:   h,
		Generation:    generation.Load(),
		BinaryVersion: v,
	}
}

// fallbackBuildVersion resolves a usable binary version when
// SetBinaryVersion has not been called (tests, go run, or
// pre-ldflags bootstraps). Tries debug.ReadBuildInfo first so
// integration tests still get the module version, then hard-falls
// to "dev" as a last resort.
//
// Cached across calls because debug.ReadBuildInfo is not free
// (walks the module graph) and the process version never changes.
var fallbackBuildCache struct {
	once sync.Once
	val  string
}

func fallbackBuildVersion() string {
	fallbackBuildCache.once.Do(func() {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			fallbackBuildCache.val = info.Main.Version
			return
		}
		fallbackBuildCache.val = "dev"
	})
	return fallbackBuildCache.val
}

// canonicalJSON marshals m with keys sorted at every level so two
// maps with the same content but different iteration order hash to
// the same digest. Only supports the subset of Go types JSON
// produces naturally - map, slice, string, number, bool, nil.
func canonicalJSON(m map[string]any) ([]byte, error) {
	return canonicalJSONValue(m)
}

func canonicalJSONValue(v any) ([]byte, error) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf strings.Builder
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			sub, err := canonicalJSONValue(x[k])
			if err != nil {
				return nil, err
			}
			buf.Write(sub)
		}
		buf.WriteByte('}')
		return []byte(buf.String()), nil
	case []any:
		var buf strings.Builder
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			sub, err := canonicalJSONValue(e)
			if err != nil {
				return nil, err
			}
			buf.Write(sub)
		}
		buf.WriteByte(']')
		return []byte(buf.String()), nil
	default:
		return json.Marshal(v)
	}
}

// ResetForTesting wipes in-memory state. Only intended for test
// helpers that need a clean slate between sub-tests.
func ResetForTesting() {
	binaryVersion.Store("")
	contentHash.Store("")
	generation.Store(0)
}
