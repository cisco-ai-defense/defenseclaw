// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package jsonc

import "testing"

func TestRemoveChildCutsOnlyTheMemberAndItsComma(t *testing.T) {
	cases := []struct{ name, in, path, want string }{
		{"first member of a line each", "{\n  a: 1,\n  b: 2,\n}", "a", "{\n  b: 2,\n}"},
		{"last member without comma", "{\n  a: 1,\n  b: 2\n}", "b", "{\n  a: 1\n}"},
		{"only member", "{\n  a: 1,\n}", "a", "{\n}"},
		{"same line", "{ a: 1, b: 2, c: 3 }", "b", "{ a: 1, c: 3 }"},
		{"same line last", "{ a: 1, b: 2 }", "b", "{ a: 1 }"},
		{"comments stay", "{\n  // keep\n  a: 1, // trailing\n  /* x */ b: 2,\n}", "a", "{\n  // keep\n  // trailing\n  /* x */ b: 2,\n}"},
		{"CRLF line", "{\r\n  a: 1,\r\n  b: 2,\r\n}", "a", "{\r\n  b: 2,\r\n}"},
		{"quoted key and nested value", "{'a': {x: [1, 2], y: '}'}, \"b\": 2}", "a", "{\"b\": 2}"},
		{"U+2028 in a comment", "{ // c\u2028 a: 1, b: 2 }", "a", "{ // c\u2028 b: 2 }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.in)
			doc, err := Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			i, ok := doc.Lookup(tc.path)
			if !ok {
				t.Fatalf("no member %q", tc.path)
			}
			if got := string(Apply(data, doc.RemoveChild(data, i))); got != tc.want {
				t.Fatalf("got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestRemoveChildOfAnArrayKeepsTheOthers(t *testing.T) {
	data := []byte("[\n  'a', // one\n  'b',\n  'c'\n]")
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(Apply(data, doc.RemoveChild(data, 2))), "[\n  'a', // one\n  'b'\n]"; got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if got, want := string(Apply(data, doc.RemoveChild(data, 1))), "[\n  'a', // one\n  'c'\n]"; got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestParseLocatesDuplicateKeysAndRejectsBrokenText(t *testing.T) {
	doc, err := Parse([]byte("\ufeff{ a: 1, 'a': 2, \\u0062: 3 }"))
	if err != nil {
		t.Fatal(err)
	}
	if i, ok := doc.Lookup("a"); !ok || i != 1 {
		t.Fatalf("Lookup(a) = %d, %v; want the last a", i, ok)
	}
	if _, ok := doc.Lookup("b"); !ok {
		t.Fatal("an escaped key name was not decoded")
	}
	for _, bad := range []string{"{ a: 1", "{ a 1 }", "[1 2]", "{ a: /* open }", "{} extra", ""} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) accepted broken text", bad)
		}
	}
}
