// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// grepGlobMatch matches name against a grep --include, --exclude or
// --exclude-dir glob the way GNU grep's fnmatch (no flags) does
// (substrate-1:GAP-0912): [!...] and [^...] negate, a ] first in a bracket
// is a member, a - first or last in a bracket is a member, a [ with no
// closing ] is a literal [, and a trailing backslash is a literal
// backslash. Go's path.Match read [!.]* as a bracket of ! and ., so
// --include='[!.]*' kept every file out and --exclude-dir='[!.]*' kept the
// dot folders out, and grep reads both. valid is false for a glob this
// matcher does not read the way fnmatch does (a POSIX class such as
// [:alpha:], an equivalence class, a collating symbol); the caller takes
// the reading that reads the file.
func grepGlobMatch(glob, name string) (match, valid bool) {
	var b strings.Builder
	for i := 0; i < len(glob); i++ {
		switch c := glob[i]; c {
		case '\\':
			if i+1 == len(glob) {
				b.WriteString(`\\`)
				continue
			}
			b.WriteByte(c)
			i++
			b.WriteByte(glob[i])
		case '[':
			j := i + 1
			negate := j < len(glob) && (glob[j] == '!' || glob[j] == '^')
			if negate {
				j++
			}
			start := j
			if j < len(glob) && glob[j] == ']' {
				j++
			}
			for j < len(glob) && glob[j] != ']' {
				if glob[j] == '[' && j+1 < len(glob) && strings.IndexByte(":=.", glob[j+1]) >= 0 {
					return false, false
				}
				if glob[j] == '\\' && j+1 < len(glob) {
					j++
				}
				j++
			}
			if j >= len(glob) {
				b.WriteString(`\[`)
				continue
			}
			b.WriteByte('[')
			if negate {
				b.WriteByte('^')
			}
			body := glob[start:j]
			for k := 0; k < len(body); k++ {
				switch ch := body[k]; {
				case ch == '\\' && k+1 < len(body):
					b.WriteByte(ch)
					k++
					b.WriteByte(body[k])
				case ch == ']', ch == '-' && (k == 0 || k == len(body)-1):
					b.WriteByte('\\')
					b.WriteByte(ch)
				default:
					b.WriteByte(ch)
				}
			}
			b.WriteByte(']')
			i = j
		default:
			b.WriteByte(c)
		}
	}
	ok, err := path.Match(b.String(), name)
	if err != nil {
		return false, false
	}
	return ok, true
}
