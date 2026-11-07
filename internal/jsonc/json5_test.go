package jsonc

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestJSON5ToJSONReadsWhatOpenClawAccepts(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want any
	}{
		"comments, bare keys, single quotes, trailing commas": {
			"{ // note\n gateway: {auth: {mode: 'token', token: 'it\\'s \"x\"',},}, /* c */ list: [1, 2,],}\n",
			map[string]any{"gateway": map[string]any{"auth": map[string]any{"mode": "token", "token": `it's "x"`}}, "list": []any{1.0, 2.0}},
		},
		"strict JSON is unchanged": {
			`{"a":{"b":"x // not a comment","c":[true,null]}}`,
			map[string]any{"a": map[string]any{"b": "x // not a comment", "c": []any{true, nil}}},
		},
		"apostrophe in a comment": {
			"{ // it's fine\n a: 1 }",
			map[string]any{"a": 1.0},
		},
		"line continuation in a string": {
			"{a: 'one \\\ntwo'}",
			map[string]any{"a": "one two"},
		},
		"bare word values stay words": {
			"{a: true, b: null, $c_1: false}",
			map[string]any{"a": true, "b": nil, "$c_1": false},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var got any
			if err := json.Unmarshal(JSON5ToJSON([]byte(tc.in)), &got); err != nil {
				t.Fatalf("not strict JSON after the rewrite: %v\n%s", err, JSON5ToJSON([]byte(tc.in)))
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

// Valid JSON5 that is not valid JSON must not make a document unreadable, and
// must keep its meaning: the reader wants one value and an unrelated number,
// escape or word elsewhere in the file must not hide it.
func TestJSON5ToJSONCoversNumbersEscapesAndWords(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want any
	}{
		"hexadecimal":            {"{a: 0x4971, b: -0X10, c: 0xFFFFFFFFFFFFFFFFFF}", map[string]any{"a": 18801.0, "b": -16.0, "c": 4722366482869645213696.0}},
		"signs and decimal dots": {"{a: +1, b: .5, c: 5., d: -.5e2, e: 1E+3, f: +.0}", map[string]any{"a": 1.0, "b": 0.5, "c": 5.0, "d": -50.0, "e": 1000.0, "f": 0.0}},
		"Infinity and NaN":       {"{a: Infinity, b: -Infinity, c: +NaN, d: [NaN]}", map[string]any{"a": nil, "b": nil, "c": nil, "d": []any{nil}}},
		"ordinary numbers":       {"{a: 0, b: -0, c: 12.5e-1, d: 7}", map[string]any{"a": 0.0, "b": 0.0, "c": 1.25, "d": 7.0}},
		"string escapes":         {`{a: '\x41\0\v\q\u0042'}`, map[string]any{"a": "A\x00\vqB"}},
		"raw control character":  {"{b: \"tab\traw\"}", map[string]any{"b": "tab\traw"}},
		"byte order mark":        {"\ufeff{a: 1}", map[string]any{"a": 1.0}},
		"other whitespace":       {"{\u00a0a\v:\f1,\u2028b: 2}", map[string]any{"a": 1.0, "b": 2.0}},
		"unicode keys":           {"{k\u00e9y: 1, \u00fcber_2: {x: 0x1}}", map[string]any{"k\u00e9y": 1.0, "\u00fcber_2": map[string]any{"x": 1.0}}},
		"comment before colon":   {"{a /* c */ : 1, b // c\n : 2}", map[string]any{"a": 1.0, "b": 2.0}},
		"words that look like numbers inside keys and strings": {
			`{Infinity1: 'NaN', x0x1: "0x10 +1 .5"}`,
			map[string]any{"Infinity1": "NaN", "x0x1": "0x10 +1 .5"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var got any
			if err := json.Unmarshal(JSON5ToJSON([]byte(tc.in)), &got); err != nil {
				t.Fatalf("not strict JSON after the rewrite: %v\n%s", err, JSON5ToJSON([]byte(tc.in)))
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

// Input that is not JSON5 stays a strict-parse failure, never a silently
// different value.
func TestJSON5ToJSONLeavesInvalidInputInvalid(t *testing.T) {
	for _, in := range []string{
		`{a: 'open`, `{a: 1`, `{a: -}`, `{a: 0x}`, `{a: +}`, `{a: .}`, `{a: '\1'}`, `{a: '\x4'}`, `{a: '\00'}`,
		"{a: 'raw\nnewline'}", `{a: 1 2}`, `{a: Infinityx}`,
	} {
		var got any
		if err := json.Unmarshal(JSON5ToJSON([]byte(in)), &got); err == nil {
			t.Errorf("%q parsed as %#v", in, got)
		}
	}
}
