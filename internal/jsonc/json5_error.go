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

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"
)

// SyntaxError is a JSON5 document that does not parse. Line and Column are
// 1-based positions in the original text (not in the strict JSON the rewrite
// produces), and Near is the text at that position, cut at the end of the
// line.
type SyntaxError struct {
	Reason string
	Line   int
	Column int
	Near   string
}

func (e *SyntaxError) Error() string {
	if e.Near == "" {
		return fmt.Sprintf("%s at line %d, column %d", e.Reason, e.Line, e.Column)
	}
	return fmt.Sprintf("%s at line %d, column %d, near %q", e.Reason, e.Line, e.Column, e.Near)
}

// UnmarshalJSON5 parses a JSON5 document into v. A document that is not
// JSON5 returns a *SyntaxError that places the problem in data itself. Any
// other failure (a value of the wrong type for v) is returned as
// encoding/json reports it.
func UnmarshalJSON5(data []byte, v any) error {
	bom := []byte("\xef\xbb\xbf")
	body := bytes.TrimPrefix(data, bom)
	var marks []rewriteMark
	rewritten, finished := rewriteJSON5(body, &marks)
	var from []int
	if finished {
		rewritten, from = stripTrailingCommas(rewritten, true)
	}
	err := json.Unmarshal(rewritten, v)
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		return err
	}
	// Offset counts the bytes read, so the byte at fault is the last one read.
	at := int(syntax.Offset) - 1
	if at < 0 {
		at = 0
	}
	src := len(body)
	switch {
	case syntax.Error() == "unexpected end of JSON input":
		// The document ended early; point at its end.
	case finished:
		src = sourceOffset(marks, from[at], len(body))
	default:
		src = sourceOffset(marks, at, len(body))
	}
	src += len(data) - len(body)
	line, column, near := locate(data, src)
	return &SyntaxError{Reason: syntax.Error(), Line: line, Column: column, Near: near}
}

// sourceOffset maps a byte of the rewritten text back to the original. out1 is
// its index before the trailing commas went.
func sourceOffset(marks []rewriteMark, out1, srcLen int) int {
	i := sort.Search(len(marks), func(i int) bool { return marks[i].outAt > out1 }) - 1
	if i < 0 {
		return 0
	}
	src := marks[i].srcAt + (out1 - marks[i].outAt)
	end := srcLen
	if i+1 < len(marks) {
		end = marks[i+1].srcAt
	}
	if src >= end && end > marks[i].srcAt {
		src = end - 1
	}
	return src
}

// locate returns the 1-based line and column (counted in characters) of data[at]
// and the text from there to the end of the line, at most 24 bytes.
func locate(data []byte, at int) (line, column int, near string) {
	if at > len(data) {
		at = len(data)
	}
	line, lineStart := 1, 0
	for i := 0; i < at; i++ {
		if isJSON5LineSeparator(data[i:]) {
			// U+2028 and U+2029 end a line in JSON5, as the rewrite reads them.
			if i+3 <= at {
				line++
				lineStart = i + 3
			}
			continue
		}
		switch data[i] {
		case '\n':
			line++
			lineStart = i + 1
		case '\r':
			if i+1 < len(data) && data[i+1] == '\n' {
				continue
			}
			line++
			lineStart = i + 1
		}
	}
	if lineStart == 0 && at >= 3 && bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
		lineStart = 3 // a byte order mark takes no column
	}
	column = utf8.RuneCount(data[lineStart:at]) + 1
	rest := data[at:]
	for i := range rest {
		if rest[i] == '\r' || rest[i] == '\n' || isJSON5LineSeparator(rest[i:]) {
			rest = rest[:i]
			break
		}
	}
	if len(rest) > 24 {
		rest = rest[:24]
		for len(rest) > 0 && !utf8.Valid(rest) {
			rest = rest[:len(rest)-1]
		}
	}
	return line, column, string(rest)
}
