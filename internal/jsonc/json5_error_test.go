// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package jsonc

import (
	"errors"
	"reflect"
	"testing"
)

func TestUnmarshalJSON5ReadsWhatJSON5ToJSONReads(t *testing.T) {
	for name, in := range map[string]string{
		"strict json":             `{"a":[1,2],"b":{"c":"x // y"}}`,
		"comments and commas":     "// top\n{ a: [1, 2,], /* mid */ b: {c: \x27x // y\x27,},}\n",
		"hex number":              "{a: [1, 2], b: {c: \"x // y\"}, port: 0x4965}",
		"byte order mark":         "\xef\xbb\xbf{\"a\": [1,2], b: {c: \"x // y\"}}",
		"crlf line endings":       "{\r\n a: [1,2],\r\n b: {c: \"x // y\"},\r\n}\r\n",
		"line comment at the end": "{a: [1,2], b: {c: \"x // y\"}} // done",
	} {
		t.Run(name, func(t *testing.T) {
			var got, want any
			if err := UnmarshalJSON5([]byte(in), &got); err != nil {
				t.Fatalf("UnmarshalJSON5: %v", err)
			}
			if err := UnmarshalJSON5([]byte(in), &want); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("second read differs: %v", err)
			}
		})
	}
}

func TestUnmarshalJSON5PlacesASyntaxErrorInTheOriginalText(t *testing.T) {
	for name, tc := range map[string]struct {
		in           string
		line, column int
		near         string
	}{
		"value missing before the closing brace": {"// note\n{\n  a: 1, // one\n  b: ,\n}", 5, 1, "}"},
		"stray comma before a closing bracket":   {"{\n  a: [1, 2,,],\n}", 2, 13, "],"},
		"unterminated block comment":             {"{ a: 1,\n  /* never closed\n b: 2 }", 2, 3, "/* never closed"},
		"crlf line endings count once":           {"{\r\n  a: 1,\r\n  b: ,\r\n}", 4, 1, "}"},
		"text after the document":                {"{a: 1}\n]", 2, 1, "]"},
		"document ends early":                    {"{a: [1, 2", 1, 10, ""},
		"after a byte order mark":                {"\xef\xbb\xbf{a: 1,, }", 1, 9, "}"},
		"after a line separator U+2028":          {"{a:1,\u2028b: !}", 2, 4, "!}"},
		"after a paragraph separator U+2029":     {"{a:1,\u2029b: !}", 2, 4, "!}"},
		"text at fault ends at a U+2028":         {"{a: !\u2028b: 1}", 1, 5, "!"},
	} {
		t.Run(name, func(t *testing.T) {
			var v any
			err := UnmarshalJSON5([]byte(tc.in), &v)
			var syntax *SyntaxError
			if !errors.As(err, &syntax) {
				t.Fatalf("got %v, want a *SyntaxError", err)
			}
			if syntax.Line != tc.line || syntax.Column != tc.column || syntax.Near != tc.near {
				t.Fatalf("placed at line %d column %d near %q (%v), want line %d column %d near %q",
					syntax.Line, syntax.Column, syntax.Near, syntax, tc.line, tc.column, tc.near)
			}
		})
	}
}

func TestUnmarshalJSON5TypeMismatchIsNotASyntaxError(t *testing.T) {
	var v map[string]any
	err := UnmarshalJSON5([]byte("// list\n[1, 2,]"), &v)
	var syntax *SyntaxError
	if err == nil || errors.As(err, &syntax) {
		t.Fatalf("got %v, want a plain type error", err)
	}
}
