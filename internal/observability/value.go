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
	"io"
	"math"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var jsonNumberPattern = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)

// Canonical payload limits are deliberately independent of destination limits.
// Projection and transport layers may impose smaller limits, but may never make
// the canonical in-memory representation unbounded.
const (
	MaxCanonicalValueDepth   = 32
	MaxCanonicalValueMembers = 8192
	MaxCanonicalValueBytes   = 1024 * 1024
)

// ValueErrorCode is a value-free reason why a canonical payload was rejected.
// Error strings intentionally contain neither payload values nor object keys.
type ValueErrorCode string

const (
	ValueErrorNotObject       ValueErrorCode = "not_object"
	ValueErrorUnsupportedType ValueErrorCode = "unsupported_type"
	ValueErrorCycle           ValueErrorCode = "cycle"
	ValueErrorNonFiniteNumber ValueErrorCode = "non_finite_number"
	ValueErrorInvalidNumber   ValueErrorCode = "invalid_number"
	ValueErrorInvalidUTF8     ValueErrorCode = "invalid_utf8"
	ValueErrorDepthLimit      ValueErrorCode = "depth_limit"
	ValueErrorMemberLimit     ValueErrorCode = "member_limit"
	ValueErrorSizeLimit       ValueErrorCode = "size_limit"
	ValueErrorDuplicateKey    ValueErrorCode = "duplicate_key"
	ValueErrorInvalidJSON     ValueErrorCode = "invalid_json"
)

// ValueError reports only a stable error code. It must remain safe for logs and
// mandatory health records even when the rejected value contains credentials.
type ValueError struct {
	Code ValueErrorCode
}

func (err *ValueError) Error() string {
	return "canonical payload rejected: " + string(err.Code)
}

func valueError(code ValueErrorCode) error {
	return &ValueError{Code: code}
}

// IsValueError reports whether err (possibly wrapped) has the requested safe
// rejection code.
func IsValueError(err error, code ValueErrorCode) bool {
	var target *ValueError
	return errors.As(err, &target) && target.Code == code
}

// Value is an immutable, bounded canonical JSON object. The encoded bytes are
// never returned directly and every decoded representation is newly allocated.
// Its zero value is invalid and cannot be marshaled.
type Value struct {
	canonical []byte
}

// NewValue validates and snapshots a JSON-compatible object. Supported nested
// values are nil, booleans, strings, finite numbers, string-keyed maps, arrays,
// and slices. Structs, pointers, functions, channels, complex numbers, and maps
// with non-string keys are rejected rather than stringified implicitly.
func NewValue(input any) (Value, error) {
	state := normalizationState{visiting: make(map[normalizationVisit]struct{})}
	normalized, err := state.normalize(reflect.ValueOf(input), 0)
	if err != nil {
		return Value{}, err
	}
	if _, ok := normalized.(map[string]any); !ok {
		return Value{}, valueError(ValueErrorNotObject)
	}
	encoded, err := marshalMinimalJSON(normalized)
	if err != nil {
		return Value{}, valueError(ValueErrorUnsupportedType)
	}
	if len(encoded) > MaxCanonicalValueBytes {
		return Value{}, valueError(ValueErrorSizeLimit)
	}
	return Value{canonical: append([]byte(nil), encoded...)}, nil
}

// ParseValue strictly parses one JSON object. Duplicate keys and trailing JSON
// values are rejected before the normal immutable snapshot is constructed.
func ParseValue(encoded []byte) (Value, error) {
	if len(encoded) > MaxCanonicalValueBytes {
		return Value{}, valueError(ValueErrorSizeLimit)
	}
	if !utf8.Valid(encoded) {
		return Value{}, valueError(ValueErrorInvalidUTF8)
	}
	if !validEscapedUnicode(encoded) {
		return Value{}, valueError(ValueErrorInvalidUTF8)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	state := decodeState{}
	decoded, err := state.decode(decoder, 0)
	if err != nil {
		return Value{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Value{}, valueError(ValueErrorInvalidJSON)
	}
	return NewValue(decoded)
}

// Bytes returns a fresh copy of the deterministic canonical JSON encoding.
func (value Value) Bytes() []byte {
	return append([]byte(nil), value.canonical...)
}

// Object decodes and returns a fresh mutable object. Mutating it cannot affect
// the Value or a Record containing the Value.
func (value Value) Object() (map[string]any, error) {
	if len(value.canonical) == 0 {
		return nil, valueError(ValueErrorInvalidJSON)
	}
	decoder := json.NewDecoder(bytes.NewReader(value.canonical))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil, valueError(ValueErrorInvalidJSON)
	}
	return object, nil
}

// Clone returns an independent immutable snapshot.
func (value Value) Clone() Value {
	return Value{canonical: value.Bytes()}
}

func (value Value) IsZero() bool {
	return len(value.canonical) == 0
}

func (value Value) MarshalJSON() ([]byte, error) {
	if value.IsZero() {
		return nil, valueError(ValueErrorInvalidJSON)
	}
	return value.Bytes(), nil
}

type normalizationVisit struct {
	typeOf  reflect.Type
	pointer uintptr
}

type normalizationState struct {
	members  int
	rawBytes int
	visiting map[normalizationVisit]struct{}
}

func (state *normalizationState) normalize(value reflect.Value, containerDepth int) (any, error) {
	if !value.IsValid() {
		return nil, nil
	}
	for value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, nil
		}
		value = value.Elem()
	}

	if value.CanInterface() {
		if number, ok := value.Interface().(json.Number); ok {
			normalized, err := normalizeJSONNumber(number)
			if err != nil {
				return nil, err
			}
			if err := state.addRawBytes(len(normalized.String())); err != nil {
				return nil, err
			}
			return normalized, nil
		}
		if _, ok := value.Interface().(json.RawMessage); ok {
			return nil, valueError(ValueErrorUnsupportedType)
		}
	}

	switch value.Kind() {
	case reflect.Bool:
		return value.Bool(), nil
	case reflect.String:
		text := value.String()
		if err := state.addString(text); err != nil {
			return nil, err
		}
		return text, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return normalizeJSONNumber(json.Number(strconv.FormatInt(value.Int(), 10)))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return normalizeJSONNumber(json.Number(strconv.FormatUint(value.Uint(), 10)))
	case reflect.Float32, reflect.Float64:
		floating := value.Float()
		if math.IsNaN(floating) || math.IsInf(floating, 0) {
			return nil, valueError(ValueErrorNonFiniteNumber)
		}
		if floating == 0 {
			return json.Number("0"), nil
		}
		bits := value.Type().Bits()
		return normalizeJSONNumber(json.Number(normalizeExponent(strconv.FormatFloat(floating, 'g', -1, bits))))
	case reflect.Map:
		if containerDepth > MaxCanonicalValueDepth {
			return nil, valueError(ValueErrorDepthLimit)
		}
		if value.Type().Key().Kind() != reflect.String {
			return nil, valueError(ValueErrorUnsupportedType)
		}
		if value.IsNil() {
			return nil, nil
		}
		if err := state.addMembers(value.Len()); err != nil {
			return nil, err
		}
		visit := normalizationVisit{typeOf: value.Type(), pointer: value.Pointer()}
		if err := state.enter(visit); err != nil {
			return nil, err
		}
		defer state.leave(visit)
		object := make(map[string]any, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			key := iterator.Key().String()
			if err := state.addString(key); err != nil {
				return nil, err
			}
			child, err := state.normalize(iterator.Value(), containerDepth+1)
			if err != nil {
				return nil, err
			}
			object[key] = child
		}
		return object, nil
	case reflect.Array:
		if containerDepth > MaxCanonicalValueDepth {
			return nil, valueError(ValueErrorDepthLimit)
		}
		if err := state.addMembers(value.Len()); err != nil {
			return nil, err
		}
		array := make([]any, value.Len())
		for index := 0; index < value.Len(); index++ {
			child, err := state.normalize(value.Index(index), containerDepth+1)
			if err != nil {
				return nil, err
			}
			array[index] = child
		}
		return array, nil
	case reflect.Slice:
		if containerDepth > MaxCanonicalValueDepth {
			return nil, valueError(ValueErrorDepthLimit)
		}
		if value.IsNil() {
			return nil, nil
		}
		if err := state.addMembers(value.Len()); err != nil {
			return nil, err
		}
		visit := normalizationVisit{typeOf: value.Type(), pointer: value.Pointer()}
		if value.Len() > 0 {
			if err := state.enter(visit); err != nil {
				return nil, err
			}
			defer state.leave(visit)
		}
		array := make([]any, value.Len())
		for index := 0; index < value.Len(); index++ {
			child, err := state.normalize(value.Index(index), containerDepth+1)
			if err != nil {
				return nil, err
			}
			array[index] = child
		}
		return array, nil
	default:
		return nil, valueError(ValueErrorUnsupportedType)
	}
}

func (state *normalizationState) addString(value string) error {
	if !utf8.ValidString(value) {
		return valueError(ValueErrorInvalidUTF8)
	}
	return state.addRawBytes(len(value))
}

func (state *normalizationState) addRawBytes(count int) error {
	if count > MaxCanonicalValueBytes-state.rawBytes {
		return valueError(ValueErrorSizeLimit)
	}
	state.rawBytes += count
	return nil
}

func (state *normalizationState) addMembers(count int) error {
	if count > MaxCanonicalValueMembers-state.members {
		return valueError(ValueErrorMemberLimit)
	}
	state.members += count
	return nil
}

func (state *normalizationState) enter(visit normalizationVisit) error {
	if _, exists := state.visiting[visit]; exists {
		return valueError(ValueErrorCycle)
	}
	state.visiting[visit] = struct{}{}
	return nil
}

func (state *normalizationState) leave(visit normalizationVisit) {
	delete(state.visiting, visit)
}

func normalizeJSONNumber(number json.Number) (json.Number, error) {
	text := number.String()
	if len(text) > MaxCanonicalValueBytes {
		return "", valueError(ValueErrorSizeLimit)
	}
	if strings.TrimSpace(text) != text {
		return "", valueError(ValueErrorInvalidNumber)
	}
	if !jsonNumberPattern.MatchString(text) {
		return "", valueError(ValueErrorInvalidNumber)
	}
	normalized, ok := normalizeExactDecimal(text)
	if !ok {
		return "", valueError(ValueErrorInvalidNumber)
	}
	return json.Number(normalized), nil
}

func normalizeExactDecimal(text string) (string, bool) {
	negative := text[0] == '-'
	if negative {
		text = text[1:]
	}
	exponentText := "0"
	if exponentAt := strings.IndexAny(text, "eE"); exponentAt >= 0 {
		exponentText = text[exponentAt+1:]
		text = text[:exponentAt]
	}
	integerPart := text
	fractionPart := ""
	if decimalAt := strings.IndexByte(text, '.'); decimalAt >= 0 {
		integerPart = text[:decimalAt]
		fractionPart = text[decimalAt+1:]
	}
	digits := strings.TrimLeft(integerPart+fractionPart, "0")
	if digits == "" {
		return "0", true
	}

	exponent := new(big.Int)
	if _, ok := exponent.SetString(exponentText, 10); !ok {
		return "", false
	}
	exponent.Sub(exponent, big.NewInt(int64(len(fractionPart))))
	trimmedDigits := strings.TrimRight(digits, "0")
	if trimmedDigits == "" {
		return "0", true
	}
	if removed := len(digits) - len(trimmedDigits); removed > 0 {
		digits = trimmedDigits
		exponent.Add(exponent, big.NewInt(int64(removed)))
	}

	scientificExponent := new(big.Int).Add(
		new(big.Int).Set(exponent),
		big.NewInt(int64(len(digits)-1)),
	)
	scientific := digits[:1]
	if len(digits) > 1 {
		scientific += "." + digits[1:]
	}
	if scientificExponent.Sign() != 0 {
		scientific += "e" + scientificExponent.String()
	}

	plain, plainOK := exactDecimalPlain(digits, exponent)
	result := scientific
	if plainOK && len(plain) <= len(scientific) {
		result = plain
	}
	if negative {
		result = "-" + result
	}
	return result, true
}

func exactDecimalPlain(digits string, exponent *big.Int) (string, bool) {
	pointBig := new(big.Int).Add(new(big.Int).Set(exponent), big.NewInt(int64(len(digits))))
	maximum := big.NewInt(MaxCanonicalValueBytes)
	minimum := new(big.Int).Neg(new(big.Int).Set(maximum))
	if pointBig.Cmp(maximum) > 0 || pointBig.Cmp(minimum) < 0 {
		return "", false
	}
	point := pointBig.Int64()
	var size int64
	switch {
	case point <= 0:
		size = 2 - point + int64(len(digits))
	case point >= int64(len(digits)):
		size = point
	default:
		size = int64(len(digits)) + 1
	}
	if size > MaxCanonicalValueBytes {
		return "", false
	}
	switch {
	case point <= 0:
		return "0." + strings.Repeat("0", int(-point)) + digits, true
	case point >= int64(len(digits)):
		return digits + strings.Repeat("0", int(point-int64(len(digits)))), true
	default:
		return digits[:point] + "." + digits[point:], true
	}
}

func normalizeExponent(number string) string {
	exponentAt := -1
	for index := 0; index < len(number); index++ {
		if number[index] == 'e' || number[index] == 'E' {
			exponentAt = index
			break
		}
	}
	if exponentAt < 0 {
		return number
	}
	mantissa := number[:exponentAt]
	exponent := number[exponentAt+1:]
	negative := false
	if len(exponent) > 0 && (exponent[0] == '+' || exponent[0] == '-') {
		negative = exponent[0] == '-'
		exponent = exponent[1:]
	}
	for len(exponent) > 1 && exponent[0] == '0' {
		exponent = exponent[1:]
	}
	if negative && exponent != "0" {
		exponent = "-" + exponent
	}
	return mantissa + "e" + exponent
}

type decodeState struct {
	members int
}

func (state *decodeState) decode(decoder *json.Decoder, containerDepth int) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, valueError(ValueErrorInvalidJSON)
	}
	switch typed := token.(type) {
	case nil, bool:
		return typed, nil
	case string:
		if err := state.addString(typed); err != nil {
			return nil, err
		}
		return typed, nil
	case json.Number:
		return normalizeJSONNumber(typed)
	case json.Delim:
		switch typed {
		case '{':
			if containerDepth > MaxCanonicalValueDepth {
				return nil, valueError(ValueErrorDepthLimit)
			}
			object := make(map[string]any)
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return nil, valueError(ValueErrorInvalidJSON)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, valueError(ValueErrorInvalidJSON)
				}
				if _, duplicate := object[key]; duplicate {
					return nil, valueError(ValueErrorDuplicateKey)
				}
				if err := state.addMember(); err != nil {
					return nil, err
				}
				if err := state.addString(key); err != nil {
					return nil, err
				}
				child, childErr := state.decode(decoder, containerDepth+1)
				if childErr != nil {
					return nil, childErr
				}
				object[key] = child
			}
			if closeToken, closeErr := decoder.Token(); closeErr != nil || closeToken != json.Delim('}') {
				return nil, valueError(ValueErrorInvalidJSON)
			}
			return object, nil
		case '[':
			if containerDepth > MaxCanonicalValueDepth {
				return nil, valueError(ValueErrorDepthLimit)
			}
			array := make([]any, 0)
			for decoder.More() {
				if err := state.addMember(); err != nil {
					return nil, err
				}
				child, childErr := state.decode(decoder, containerDepth+1)
				if childErr != nil {
					return nil, childErr
				}
				array = append(array, child)
			}
			if closeToken, closeErr := decoder.Token(); closeErr != nil || closeToken != json.Delim(']') {
				return nil, valueError(ValueErrorInvalidJSON)
			}
			return array, nil
		}
	}
	return nil, valueError(ValueErrorInvalidJSON)
}

func (state *decodeState) addString(value string) error {
	if !utf8.ValidString(value) {
		return valueError(ValueErrorInvalidUTF8)
	}
	return nil
}

func (state *decodeState) addMember() error {
	if state.members == MaxCanonicalValueMembers {
		return valueError(ValueErrorMemberLimit)
	}
	state.members++
	return nil
}

func marshalMinimalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	encoded = unescapeJSONLineSeparators(encoded)
	return append([]byte(nil), encoded...), nil
}

// encoding/json escapes U+2028 and U+2029 for JavaScript embedding even when
// HTML escaping is disabled. Canonical JSON permits both characters literally.
// Only replace a real JSON Unicode escape (an odd backslash run); a blanket
// byte replacement would corrupt user text containing the six characters
// "\\u2028" or "\\u2029".
func unescapeJSONLineSeparators(encoded []byte) []byte {
	result := make([]byte, 0, len(encoded))
	for index := 0; index < len(encoded); {
		if encoded[index] != '\\' {
			result = append(result, encoded[index])
			index++
			continue
		}
		start := index
		for index < len(encoded) && encoded[index] == '\\' {
			index++
		}
		slashes := index - start
		separator := ""
		if slashes%2 == 1 && index+5 <= len(encoded) {
			switch string(encoded[index : index+5]) {
			case "u2028":
				separator = "\u2028"
			case "u2029":
				separator = "\u2029"
			}
		}
		if separator == "" {
			result = append(result, encoded[start:index]...)
			continue
		}
		result = append(result, encoded[start:index-1]...)
		result = append(result, separator...)
		index += 5
	}
	return result
}

func validEscapedUnicode(encoded []byte) bool {
	inString := false
	for index := 0; index < len(encoded); index++ {
		switch encoded[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(encoded) {
				continue
			}
			index++
			if encoded[index] != 'u' || index+4 >= len(encoded) {
				continue
			}
			codeUnit, ok := parseHexCodeUnit(encoded[index+1 : index+5])
			if !ok {
				continue
			}
			index += 4
			switch {
			case codeUnit >= 0xd800 && codeUnit <= 0xdbff:
				if index+6 >= len(encoded) || encoded[index+1] != '\\' || encoded[index+2] != 'u' {
					return false
				}
				low, lowOK := parseHexCodeUnit(encoded[index+3 : index+7])
				if !lowOK || low < 0xdc00 || low > 0xdfff {
					return false
				}
				index += 6
			case codeUnit >= 0xdc00 && codeUnit <= 0xdfff:
				return false
			}
		}
	}
	return true
}

func parseHexCodeUnit(encoded []byte) (uint16, bool) {
	if len(encoded) != 4 {
		return 0, false
	}
	var result uint16
	for _, character := range encoded {
		result <<= 4
		switch {
		case character >= '0' && character <= '9':
			result |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			result |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			result |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}
