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

// Syntax the rewrite does not cover must stay a strict-parse failure, never a
// silently different value.
func TestJSON5ToJSONLeavesUnsupportedSyntaxInvalid(t *testing.T) {
	for _, in := range []string{`{a: 0x10}`, `{a: Infinity}`, `{a: 'open`, `{a: 1`} {
		var got any
		if err := json.Unmarshal(JSON5ToJSON([]byte(in)), &got); err == nil {
			t.Errorf("%q parsed as %#v", in, got)
		}
	}
}
