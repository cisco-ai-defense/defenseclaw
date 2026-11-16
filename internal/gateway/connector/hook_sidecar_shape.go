// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

// The shapes of the hooks/.hookcfg files every reader agrees on: the native
// Windows hook (readHookSidecar), status (fail_mode.py), the shared Unix
// hooks (_hardening.sh) and the writers here, which must never turn state a
// reader closes on into state it opens on when they rewrite it.

// hookSidecarJSONFields are the top-level fields of the JSON sidecar.
var hookSidecarJSONFields = [...]string{"version", "gateway_addr", "fail_modes", "legacy_fail_mode", "fail_mode_sources", "legacy_fail_mode_source"}

// HookSidecarMaxBytes bounds a hooks/.hookcfg document. Setup writes a few
// hundred bytes; a larger file is malformed state.
const HookSidecarMaxBytes = 64 << 10

// hookSidecarMaxDepth bounds the nesting of a JSON sidecar. Setup writes two
// levels; a deeper document is malformed state.
const hookSidecarMaxDepth = 32

// HookSidecarJSONMalformed returns why a hooks/.hookcfg document that parses
// as JSON is not a v2 sidecar, or nil when it is one. It is the contract the
// native Windows hook (readHookSidecar) and status (fail_mode.py) close on
// anything outside of: one JSON object of at most HookSidecarMaxBytes,
// nested at most hookSidecarMaxDepth levels, with no key given twice and no
// top-level key naming a field in another case (HookSidecarJSONAmbiguous); a
// version written as an integer from 2 to 2^63-1 (not 2.0, 2e0 or "2"); a
// gateway_addr, legacy_fail_mode and legacy_fail_mode_source that are strings
// or null; and a fail_modes and fail_mode_sources that, when present, are
// objects (not null) of strings or null.
func HookSidecarJSONMalformed(data []byte) error {
	if len(data) > HookSidecarMaxBytes {
		return errors.New("parse hook config sidecar: larger than 64 KiB")
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) != nil || doc == nil {
		return errors.New("parse hook config sidecar: not one JSON object")
	}
	if HookSidecarJSONAmbiguous(data) {
		return errAmbiguousHookConfigSidecar
	}
	if HookSidecarJSONDepth(data) > hookSidecarMaxDepth {
		return errors.New("parse hook config sidecar: nested deeper than 32 levels")
	}
	if !hookSidecarVersionToken(doc["version"]) {
		return errors.New("parse hook config sidecar: version is not written as an integer from 2 to 2^63-1")
	}
	for _, field := range [...]string{"gateway_addr", "legacy_fail_mode", "legacy_fail_mode_source"} {
		if raw, ok := doc[field]; ok && !jsonStringOrNull(raw) {
			return errors.New("parse hook config sidecar: " + field + " is not a string")
		}
	}
	nullModes := false
	for _, field := range [...]string{"fail_mode_sources", "fail_modes"} {
		raw, ok := doc[field]
		if !ok {
			continue
		}
		if field == "fail_modes" && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			nullModes = true
			continue
		}
		var entries map[string]json.RawMessage
		if json.Unmarshal(raw, &entries) != nil || entries == nil {
			return errors.New("parse hook config sidecar: " + field + " is not an object")
		}
		for _, value := range entries {
			if !jsonStringOrNull(value) {
				return errors.New("parse hook config sidecar: a " + field + " entry is not a string")
			}
		}
	}
	if nullModes {
		return errHookSidecarNullFailModes
	}
	return nil
}

// errHookSidecarNullFailModes is a sidecar that meets every other rule of
// HookSidecarJSONMalformed but whose fail_modes is null. Every reader closes
// on it. An unmanaged writer may rebuild the map from the connector records
// that corroborate it (recoverFlatHookFailModes, GAP-0512); every other
// rewrite refuses it.
var errHookSidecarNullFailModes = errors.New("parse hook config sidecar: fail_modes is not an object")

// hookSidecarRewriteRefused returns why a writer must not carry a JSON
// sidecar into a rewrite: anything a reader on any OS closes on. That is
// HookSidecarJSONMalformed, and also a backslash anywhere in the document,
// which the shared Unix hooks (_hardening.sh) close on so that they can read
// every token as written; no writer emits one. A rewrite of such state would
// settle it into a document a reader opens on.
func hookSidecarRewriteRefused(data []byte) error {
	if bytes.IndexByte(data, '\\') >= 0 {
		return errors.New("parse hook config sidecar: a backslash escape, which the shared hooks close on")
	}
	return HookSidecarJSONMalformed(data)
}

// hookSidecarVersionToken reports a version written as an integer from 2 to
// 2^63-1: digits only, no sign, fraction, exponent or leading zero.
func hookSidecarVersionToken(raw json.RawMessage) bool {
	token := bytes.TrimSpace(raw)
	if len(token) == 0 || token[0] < '1' || token[0] > '9' {
		return false
	}
	for _, c := range token {
		if c < '0' || c > '9' {
			return false
		}
	}
	version, err := strconv.ParseInt(string(token), 10, 64)
	return err == nil && version >= 2
}

// jsonStringOrNull reports a JSON string or null.
func jsonStringOrNull(raw json.RawMessage) bool {
	var value *string
	return json.Unmarshal(raw, &value) == nil
}

// HookSidecarJSONDepth is the deepest object or array nesting of a JSON
// document that already parsed.
func HookSidecarJSONDepth(data []byte) int {
	depth, deepest := 0, 0
	inString, escaped := false, false
	for _, c := range data {
		switch {
		case inString && escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case inString && c == '"':
			inString = false
		case inString:
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			depth++
			if depth > deepest {
				deepest = depth
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return deepest
}

// HookSidecarJSONAmbiguous reports a JSON sidecar that names a key twice in
// one object, or a top-level key that names a sidecar field in another case.
// Readers take the last of two keys and encoding/json folds case, so such a
// document reads differently to each reader, and a rewrite would settle it
// either way: it is malformed state. data must be valid JSON.
func HookSidecarJSONAmbiguous(data []byte) bool {
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) == nil {
		for key := range doc {
			for _, field := range hookSidecarJSONFields {
				if key != field && strings.EqualFold(key, field) {
					return true
				}
			}
		}
	}
	return jsonDuplicateKey(data)
}

// hookSidecarJSONMaxNesting bounds the nesting jsonDuplicateKey walks: the
// writers nest two levels, and encoding/json's own limit is not the same in
// every Go release.
const hookSidecarJSONMaxNesting = 10000

// jsonDuplicateKey reports an object of data that names a key twice, data
// nested deeper than hookSidecarJSONMaxNesting, or data that is not JSON. It
// walks the tokens without recursion, so the nesting of the document never
// grows the stack.
func jsonDuplicateKey(data []byte) bool {
	type frame struct {
		keys      map[string]struct{} // nil for an array
		expectKey bool
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber() // a number too large for a float64 is still JSON
	var stack []*frame
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return false
		}
		if err != nil {
			return true
		}
		var top *frame
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if top != nil && top.keys != nil {
					top.expectKey = true // this container is the value
				}
				next := &frame{}
				if delim == '{' {
					next.keys = map[string]struct{}{}
					next.expectKey = true
				}
				stack = append(stack, next)
				if len(stack) > hookSidecarJSONMaxNesting {
					return true
				}
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil || top.keys == nil {
			continue
		}
		if top.expectKey {
			key, _ := token.(string)
			if _, seen := top.keys[key]; seen {
				return true
			}
			top.keys[key] = struct{}{}
			top.expectKey = false
			continue
		}
		top.expectKey = true
	}
}

// ParseLegacyHookSidecar reads the KEY=value hooks/.hookcfg that releases
// before 0.8.10 wrote. Every line is blank, a # comment, or [export ]KEY=value
// with a shell-name key, and every key is given once; ok is false for any
// other document (JSON, a byte-order mark or a comment in front of other
// text, a line that is not KEY=value, a key given twice, more than
// HookSidecarMaxBytes, which every reader closes on), which is malformed
// state, never read for a value.
func ParseLegacyHookSidecar(data []byte) (values map[string]string, ok bool) {
	if len(data) > HookSidecarMaxBytes {
		return nil, false
	}
	values = map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		key = strings.TrimSpace(key)
		if _, seen := values[key]; !found || !legacyHookSidecarKey(key) || seen {
			return nil, false
		}
		values[key] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return values, true
}

// legacyHookSidecarKey reports a shell variable name.
func legacyHookSidecarKey(key string) bool {
	if key == "" || (key[0] >= '0' && key[0] <= '9') {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// flatHookRecordValue reads one key of a hooks/.hookcfg.<connector> record as
// the shared Unix hooks do (defenseclaw_flat_hookcfg_value): KEY=value lines
// with an upper-case key, each key once, every line ended by a newline, no
// NUL byte. ok is false for any other record. Unlike the shared hooks it has
// no size bound: the unmanaged runtime check keeps reading oversized records
// (TestUnmanagedHookRuntimeContractRetainsUnboundedLegacyReads), which the
// hooks themselves run closed.
func flatHookRecordValue(data []byte, wanted string) (value string, ok bool) {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.IndexByte(data, 0) >= 0 {
		return "", false
	}
	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(data[:len(data)-1]), "\n") {
		key, rest, found := strings.Cut(line, "=")
		if _, dup := seen[key]; !found || dup || !flatHookRecordKey(key) {
			return "", false
		}
		seen[key] = struct{}{}
		if key == wanted {
			value, ok = rest, true
		}
	}
	return value, ok
}

// flatHookRecordKey reports an upper-case shell variable name.
func flatHookRecordKey(key string) bool {
	if key == "" || (key[0] >= '0' && key[0] <= '9') {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
