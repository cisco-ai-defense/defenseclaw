// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestValueCanonicalEncodingAndMinimalEscapes(t *testing.T) {
	negativeZero := math.Copysign(0, -1)
	value, err := NewValue(map[string]any{
		"z": "<>&\u2028\u2029",
		"a": map[string]any{"negative_zero": negativeZero, "decimal": json.Number("1.2300")},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":{\"decimal\":1.23,\"negative_zero\":0},\"z\":\"<>&\u2028\u2029\"}"
	if got := string(value.Bytes()); got != want {
		t.Fatalf("canonical JSON mismatch\n got: %s\nwant: %s", got, want)
	}

	first := value.Bytes()
	first[0] = '['
	if got := string(value.Bytes()); got != want {
		t.Fatalf("Bytes exposed mutable state: %s", got)
	}
}

func TestValueBackspaceAndFormFeedCanonicalEncoding(t *testing.T) {
	value, err := NewValue(map[string]any{
		"\f": "\b",
		"nested": []any{
			"prefix\bsuffix",
			map[string]any{"value": "prefix\fsuffix"},
		},
		"\b": "\f",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"\\b\":\"\\f\",\"\\f\":\"\\b\",\"nested\":[\"prefix\\bsuffix\",{\"value\":\"prefix\\fsuffix\"}]}"
	if got := string(value.Bytes()); got != want {
		t.Fatalf("canonical control-character JSON mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestValueMinimalLineSeparatorEscapesPreserveLiteralBackslashes(t *testing.T) {
	input := map[string]any{
		"literal_escape":       `\u2028\u2029`,
		"separator":            "\u2028\u2029",
		"slash_then_separator": "\\\u2028\\\u2029",
	}
	value, err := NewValue(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded := value.Bytes()
	if !json.Valid(encoded) {
		t.Fatalf("canonical output is invalid JSON: %q", encoded)
	}
	var decoded map[string]string
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for key, want := range input {
		if got := decoded[key]; got != want {
			t.Fatalf("%s round trip = %q, want %q", key, got, want)
		}
	}
	if !bytes.Contains(encoded, []byte(`"literal_escape":"\\u2028\\u2029"`)) {
		t.Fatalf("literal escape spelling was rewritten: %q", encoded)
	}

	parsed, err := ParseValue([]byte(`{"literal_escape":"\\u2028\\u2029"}`))
	if err != nil {
		t.Fatal(err)
	}
	parsedObject, err := parsed.Object()
	if err != nil {
		t.Fatal(err)
	}
	if got := parsedObject["literal_escape"]; got != `\u2028\u2029` {
		t.Fatalf("parsed literal escape = %q", got)
	}
}

func TestValueCanonicalExponentVectors(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{name: "positive exponent", input: 1e20, want: `{"n":1e20}`},
		{name: "negative exponent", input: 1e-9, want: `{"n":1e-9}`},
		{name: "negative zero", input: math.Copysign(0, -1), want: `{"n":0}`},
		{name: "seven digit negative exponent", input: 1e-7, want: `{"n":1e-7}`},
		{name: "smallest subnormal", input: math.SmallestNonzeroFloat64, want: `{"n":5e-324}`},
		{name: "largest finite", input: math.MaxFloat64, want: `{"n":1.7976931348623157e308}`},
		{name: "number positive sign and zero", input: json.Number("1e+09"), want: `{"n":1e9}`},
		{name: "number negative exponent zero", input: json.Number("1e-09"), want: `{"n":1e-9}`},
		{name: "negative zero exponent", input: json.Number("-0e+08"), want: `{"n":0}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := NewValue(map[string]any{"n": test.input})
			if err != nil {
				t.Fatal(err)
			}
			if got := string(value.Bytes()); got != test.want {
				t.Fatalf("got %s, want %s", got, test.want)
			}
		})
	}
}

func TestValueLosslessDecimalAndExtremeExponentVectors(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "12345678901234567890.12345678901234567890",
			want:  `{"n":12345678901234567890.1234567890123456789}`,
		},
		{input: "1e9223372036854775807", want: `{"n":1e9223372036854775807}`},
		{input: "1e-9223372036854775808", want: `{"n":1e-9223372036854775808}`},
		{input: "1e92233720368547758070", want: `{"n":1e92233720368547758070}`},
		{input: "1e-92233720368547758080", want: `{"n":1e-92233720368547758080}`},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			value, err := NewValue(map[string]any{"n": json.Number(test.input)})
			if err != nil {
				t.Fatal(err)
			}
			if got := string(value.Bytes()); got != test.want {
				t.Fatalf("got %s, want %s", got, test.want)
			}
		})
	}
}

func TestValueEquivalentNumberSpellingsHaveOneCanonicalEncoding(t *testing.T) {
	inputs := []any{
		json.Number("100000000000000000000"),
		json.Number("1e20"),
		json.Number("100000000000000000000.0"),
		1e20,
	}
	for _, input := range inputs {
		value, err := NewValue(map[string]any{"n": input})
		if err != nil {
			t.Fatalf("%v: %v", input, err)
		}
		if got := string(value.Bytes()); got != `{"n":1e20}` {
			t.Fatalf("%v canonicalized as %s", input, got)
		}
	}
}

func FuzzParseValueCanonicalRoundTrip(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"text":"person@example.test","nested":{"items":[true,null,1.2300]}}`),
		[]byte(`{"escaped":"\\u2028","separator":" "}`),
		[]byte(`{"duplicate":1,"duplicate":2}`),
		[]byte(`{"truncated":`),
		{0xff, 0xfe, '{', '}'},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, encoded []byte) {
		value, err := ParseValue(encoded)
		if err != nil {
			var safe *ValueError
			if !errors.As(err, &safe) || safe.Code == "" {
				t.Fatalf("ParseValue returned a non-value-safe error: %T %v", err, err)
			}
			return
		}

		canonical := value.Bytes()
		if len(canonical) > MaxCanonicalValueBytes || !json.Valid(canonical) {
			t.Fatalf("successful parse produced invalid canonical JSON of %d bytes", len(canonical))
		}
		reparsed, err := ParseValue(canonical)
		if err != nil {
			t.Fatalf("canonical output did not reparse: %v", err)
		}
		if !bytes.Equal(canonical, reparsed.Bytes()) {
			t.Fatalf("canonical reparse changed bytes")
		}

		object, err := value.Object()
		if err != nil {
			t.Fatalf("successful value did not decode: %v", err)
		}
		rebuilt, err := NewValue(object)
		if err != nil {
			t.Fatalf("decoded object did not rebuild: %v", err)
		}
		if !bytes.Equal(canonical, rebuilt.Bytes()) {
			t.Fatalf("object round trip changed canonical bytes")
		}

		object["fuzzer_mutation"] = "must-not-alias"
		canonical[0] = '['
		if !bytes.Equal(value.Bytes(), reparsed.Bytes()) {
			t.Fatalf("value accessors exposed mutable state")
		}
	})
}

func TestValueNormalizesNearLimitTrailingZerosInBulk(t *testing.T) {
	// This is intentionally close to the raw value ceiling. A per-zero big.Int
	// loop turns this valid input into CPU/GC amplification on the producer path.
	zeros := strings.Repeat("0", MaxCanonicalValueBytes-32)
	value, err := NewValue(map[string]any{"n": json.Number("1." + zeros)})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(value.Bytes()); got != `{"n":1}` {
		t.Fatalf("trailing-zero decimal = %s", got)
	}
}

func TestValueRejectsOneOverRawNumberBeforeNormalization(t *testing.T) {
	oversize := json.Number("1." + strings.Repeat("0", MaxCanonicalValueBytes))
	_, err := NewValue(map[string]any{"n": oversize})
	if !IsValueError(err, ValueErrorSizeLimit) {
		t.Fatalf("oversize raw number error = %v", err)
	}
}

func TestValueSnapshotsInputsAndOutputs(t *testing.T) {
	child := []any{"original"}
	input := map[string]any{"child": child}
	value, err := NewValue(input)
	if err != nil {
		t.Fatal(err)
	}
	child[0] = "changed"
	input["new"] = true

	object, err := value.Object()
	if err != nil {
		t.Fatal(err)
	}
	decodedChild := object["child"].([]any)
	if decodedChild[0] != "original" {
		t.Fatalf("input mutation changed Value: %#v", decodedChild)
	}
	decodedChild[0] = "output-changed"
	delete(object, "child")

	again, err := value.Object()
	if err != nil {
		t.Fatal(err)
	}
	if again["child"].([]any)[0] != "original" {
		t.Fatalf("output mutation changed Value: %#v", again)
	}
	if got := string(value.Clone().Bytes()); got != `{"child":["original"]}` {
		t.Fatalf("clone mismatch: %s", got)
	}
}

func TestValueRejectsNonObjectAndUnsupportedValues(t *testing.T) {
	tests := []struct {
		name  string
		input any
		code  ValueErrorCode
	}{
		{name: "nil", input: nil, code: ValueErrorNotObject},
		{name: "array root", input: []any{}, code: ValueErrorNotObject},
		{name: "non-string map key", input: map[int]any{1: true}, code: ValueErrorUnsupportedType},
		{name: "struct", input: map[string]any{"value": struct{}{}}, code: ValueErrorUnsupportedType},
		{name: "pointer", input: map[string]any{"value": new(string)}, code: ValueErrorUnsupportedType},
		{name: "raw message", input: map[string]any{"value": json.RawMessage(`{"x":1}`)}, code: ValueErrorUnsupportedType},
		{name: "NaN", input: map[string]any{"value": math.NaN()}, code: ValueErrorNonFiniteNumber},
		{name: "positive infinity", input: map[string]any{"value": math.Inf(1)}, code: ValueErrorNonFiniteNumber},
		{name: "invalid number", input: map[string]any{"value": json.Number("01")}, code: ValueErrorInvalidNumber},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewValue(test.input)
			if !IsValueError(err, test.code) {
				t.Fatalf("got %v, want code %s", err, test.code)
			}
		})
	}
}

func TestValueRejectsCyclesButAllowsSharedChildren(t *testing.T) {
	cyclicMap := map[string]any{}
	cyclicMap["self"] = cyclicMap
	if _, err := NewValue(cyclicMap); !IsValueError(err, ValueErrorCycle) {
		t.Fatalf("cyclic map error = %v", err)
	}

	cyclicSlice := make([]any, 1)
	cyclicSlice[0] = cyclicSlice
	if _, err := NewValue(map[string]any{"slice": cyclicSlice}); !IsValueError(err, ValueErrorCycle) {
		t.Fatalf("cyclic slice error = %v", err)
	}

	shared := map[string]any{"value": true}
	if _, err := NewValue(map[string]any{"left": shared, "right": shared}); err != nil {
		t.Fatalf("shared non-cyclic object rejected: %v", err)
	}
}

func TestValueRejectsInvalidUTF8WithoutEcho(t *testing.T) {
	secret := "do-not-echo"
	invalid := string([]byte{0xff, 0xfe}) + secret
	for _, input := range []any{
		map[string]any{"value": invalid},
		map[string]any{invalid: true},
	} {
		_, err := NewValue(input)
		if !IsValueError(err, ValueErrorInvalidUTF8) {
			t.Fatalf("got %v", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error echoed payload content: %v", err)
		}
	}
}

func TestValueContainerDepthBoundary(t *testing.T) {
	allowed := nestedObject(MaxCanonicalValueDepth)
	if _, err := NewValue(allowed); err != nil {
		t.Fatalf("depth %d rejected: %v", MaxCanonicalValueDepth, err)
	}
	if _, err := NewValue(nestedObject(MaxCanonicalValueDepth + 1)); !IsValueError(err, ValueErrorDepthLimit) {
		t.Fatalf("depth boundary error = %v", err)
	}

	allowedJSON, err := NewValue(allowed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseValue(allowedJSON.Bytes()); err != nil {
		t.Fatalf("parser rejected depth boundary: %v", err)
	}
	tooDeepJSON, err := json.Marshal(nestedObject(MaxCanonicalValueDepth + 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseValue(tooDeepJSON); !IsValueError(err, ValueErrorDepthLimit) {
		t.Fatalf("parser depth boundary error = %v", err)
	}
}

func nestedObject(levelsBelowRoot int) map[string]any {
	root := map[string]any{}
	current := root
	for range levelsBelowRoot {
		next := map[string]any{}
		current["next"] = next
		current = next
	}
	current["leaf"] = true
	return root
}

func TestValueAggregateMemberBoundary(t *testing.T) {
	allowed := make([]any, MaxCanonicalValueMembers-1)
	if _, err := NewValue(map[string]any{"values": allowed}); err != nil {
		t.Fatalf("exact member boundary rejected: %v", err)
	}
	over := make([]any, MaxCanonicalValueMembers)
	if _, err := NewValue(map[string]any{"values": over}); !IsValueError(err, ValueErrorMemberLimit) {
		t.Fatalf("member boundary error = %v", err)
	}

	encoded := []byte(`{"values":[` + strings.Repeat("null,", MaxCanonicalValueMembers-1) + `null]}`)
	if _, err := ParseValue(encoded); !IsValueError(err, ValueErrorMemberLimit) {
		t.Fatalf("parser member boundary error = %v", err)
	}
}

func TestValueEncodedSizeBoundary(t *testing.T) {
	const overhead = len(`{"value":""}`)
	allowedText := strings.Repeat("x", MaxCanonicalValueBytes-overhead)
	value, err := NewValue(map[string]any{"value": allowedText})
	if err != nil {
		t.Fatalf("exact size boundary rejected: %v", err)
	}
	if got := len(value.Bytes()); got != MaxCanonicalValueBytes {
		t.Fatalf("encoded size = %d", got)
	}
	if _, err := NewValue(map[string]any{"value": allowedText + "x"}); !IsValueError(err, ValueErrorSizeLimit) {
		t.Fatalf("size boundary error = %v", err)
	}
	if _, err := ParseValue(append(value.Bytes(), ' ')); !IsValueError(err, ValueErrorSizeLimit) {
		t.Fatalf("raw parser size boundary error = %v", err)
	}
}

func TestParseValueStrictJSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		code ValueErrorCode
	}{
		{name: "duplicate key", json: `{"safe":1,"safe":2}`, code: ValueErrorDuplicateKey},
		{name: "trailing value", json: `{"safe":1}{}`, code: ValueErrorInvalidJSON},
		{name: "array root", json: `[]`, code: ValueErrorNotObject},
		{name: "invalid syntax", json: `{"safe":`, code: ValueErrorInvalidJSON},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseValue([]byte(test.json))
			if !IsValueError(err, test.code) {
				t.Fatalf("got %v, want %s", err, test.code)
			}
		})
	}
}

func TestParseValueRejectsUnpairedEscapedSurrogates(t *testing.T) {
	for _, encoded := range []string{
		`{"value":"\ud800"}`,
		`{"value":"\ud800\u0041"}`,
		`{"value":"\udc00"}`,
	} {
		_, err := ParseValue([]byte(encoded))
		if !IsValueError(err, ValueErrorInvalidUTF8) {
			t.Fatalf("unpaired surrogate error = %v", err)
		}
	}
	value, err := ParseValue([]byte(`{"value":"\ud83d\ude00"}`))
	if err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
	if got := string(value.Bytes()); got != `{"value":"😀"}` {
		t.Fatalf("surrogate canonicalization = %s", got)
	}
}

func TestZeroValueCannotMarshal(t *testing.T) {
	if _, err := json.Marshal(Value{}); !IsValueError(err, ValueErrorInvalidJSON) {
		t.Fatalf("zero marshal error = %v", err)
	}
}
