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

package safetext

import (
	"fmt"
	"unicode/utf8"
)

// JSON makes encoded JSON (from encoding/json) safe to print on a terminal.
// encoding/json escapes C0 controls but writes DEL, the C1 controls and the
// bidirectional and zero-width format characters as they are; JSON prints
// them as \u escapes instead, so the document means the same and shows
// nothing hidden. With UseASCII on, every character outside ASCII is
// escaped. Bytes that are not UTF-8 (encoding/json never writes them) become
// U+FFFD.
func JSON(b []byte) []byte {
	clean := true
	for _, c := range b {
		if c >= 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return b
	}
	ascii := asciiOnly.Load()
	out := make([]byte, 0, len(b)+16)
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			out = append(out, `\ufffd`...)
		case r == 0x7f || (r >= 0x80 && r <= 0x9f) || isFormat(r) || (ascii && r >= utf8.RuneSelf):
			if r > 0xffff {
				r -= 0x10000
				out = fmt.Appendf(out, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			} else {
				out = fmt.Appendf(out, `\u%04x`, r)
			}
		default:
			out = append(out, b[i:i+size]...)
		}
		i += size
	}
	return out
}
