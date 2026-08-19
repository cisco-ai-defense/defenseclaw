// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// writeSortedJSON serialises v to path with:
//   - alphabetically-sorted top-level and nested map keys (encoding/json
//     already sorts map keys when marshalling),
//   - two-space indent, no HTML escaping,
//     (< > & are common in file paths but never in our schema; disabled so
//     the output looks like the schema we specified rather than <),
//   - LF line endings (Windows CRLF would inflate diffs and break byte-
//     equality across bash/pwsh hosts),
//   - a single trailing LF.
//
// v MUST be a value that marshals to a JSON object composed of maps for
// stable key order. Nested structs would preserve declaration order,
// which is fine for a single Go build but fragile across refactors;
// callers use maps so the byte-stability contract is the type system's
// responsibility, not the developer's memory.
func writeSortedJSON(path string, v any) error {
	buf, err := marshalSortedJSON(v)
	if err != nil {
		return err
	}
	// Write with 0o644; these files are build artefacts consumed by AVC's
	// pipeline and do not carry secrets. Callers that need stricter mode
	// bits can chmod after the fact.
	return os.WriteFile(path, buf, 0o644)
}

// marshalSortedJSON is the pure-in-memory sibling of writeSortedJSON,
// used by unit tests to assert byte-stability without touching disk.
func marshalSortedJSON(v any) ([]byte, error) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode json: %w", err)
	}
	// json.Encoder always appends exactly one '\n' after Encode; keep
	// the assertion explicit so a future refactor cannot silently drop
	// the trailing newline.
	b := out.Bytes()
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return nil, fmt.Errorf("marshalSortedJSON: encoder output missing trailing LF")
	}
	return b, nil
}
