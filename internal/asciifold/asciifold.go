// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package asciifold lowers ASCII letters only. strings.ToLower maps runes, and
// a rune's lower case can be longer (U+023A, 2 bytes, lowers to 3) or shorter
// (U+212A and U+0130 lower to ASCII k and i) than the rune itself, so an
// offset found in strings.ToLower(s) is not an offset of s. Every offset found
// in Lower(s) is.
package asciifold

import "unsafe"

// Lower returns s with A-Z lowered to a-z and every other byte as it is: the
// result has the length of s and the bytes of s at every offset but its ASCII
// capitals. It returns s itself, with no allocation, when s has no ASCII
// capital. For ASCII text it is strings.ToLower.
func Lower(s string) string {
	first := -1
	for index := 0; index < len(s); index++ {
		if c := s[index]; 'A' <= c && c <= 'Z' {
			first = index
			break
		}
	}
	if first < 0 {
		return s
	}
	// One copy, then the capitals are lowered in place: one allocation and
	// no per-byte append, so it is no slower than strings.ToLower on any
	// ASCII text, sparse or dense in capitals.
	lowered := make([]byte, len(s))
	copy(lowered, s)
	for index := first; index < len(lowered); index++ {
		if c := lowered[index]; 'A' <= c && c <= 'Z' {
			lowered[index] = c + 'a' - 'A'
		}
	}
	// lowered is never written again, so it can back the string without a
	// second copy (what strings.Builder.String does).
	return unsafe.String(unsafe.SliceData(lowered), len(lowered))
}
