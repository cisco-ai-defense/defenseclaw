// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package jsonc

// JSON5ToJSON rewrites a JSON5 document into strict JSON for encoding/json:
// comments and trailing commas go, unquoted object keys and single-quoted
// strings are quoted, and a backslash-newline continuation inside a string is
// dropped. OpenClaw reads openclaw.json as JSON5, so a reader that only takes
// strict JSON misreads a file the product itself accepts.
//
// It is a normalizer, not a validator: syntax it does not rewrite (hex or
// signed numbers, Infinity, NaN) stays as written, and the caller's strict
// parse then fails, which the caller must treat as "could not read".
func JSON5ToJSON(data []byte) []byte {
	out := make([]byte, 0, len(data)+16)
	for i := 0; i < len(data); {
		b := data[i]
		switch {
		case b == '"' || b == '\'':
			var next int
			out, next = appendJSON5String(out, data, i)
			i = next
		case b == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' && data[i] != '\r' {
				i++
			}
		case b == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && (data[i] != '*' || data[i+1] != '/') {
				i++
			}
			i = min(i+2, len(data))
		case isJSON5IdentStart(b):
			j := i + 1
			for j < len(data) && (isJSON5IdentStart(data[j]) || data[j] >= '0' && data[j] <= '9') {
				j++
			}
			k := j
			for k < len(data) && (data[k] == ' ' || data[k] == '\t' || data[k] == '\n' || data[k] == '\r') {
				k++
			}
			if k < len(data) && data[k] == ':' {
				out = append(out, '"')
				out = append(out, data[i:j]...)
				out = append(out, '"')
			} else {
				out = append(out, data[i:j]...)
			}
			i = j
		default:
			out = append(out, b)
			i++
		}
	}
	return stripJSONCTrailingCommas(out)
}

func isJSON5IdentStart(b byte) bool {
	return b == '_' || b == '$' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// appendJSON5String copies the string that starts at data[start] as a
// double-quoted JSON string and returns the index after its closing quote.
func appendJSON5String(out, data []byte, start int) ([]byte, int) {
	quote := data[start]
	out = append(out, '"')
	i := start + 1
	for i < len(data) {
		b := data[i]
		switch {
		case b == quote:
			return append(out, '"'), i + 1
		case b == '\\' && i+1 < len(data):
			next := data[i+1]
			switch next {
			case '\n':
				i += 2
			case '\r':
				i += 2
				if i < len(data) && data[i] == '\n' {
					i++
				}
			case '\'':
				out = append(out, '\'')
				i += 2
			default:
				out = append(out, b, next)
				i += 2
			}
		case b == '"':
			out = append(out, '\\', '"')
			i++
		default:
			out = append(out, b)
			i++
		}
	}
	// Unterminated: hand back what was read; the strict parse rejects it.
	return out, i
}
