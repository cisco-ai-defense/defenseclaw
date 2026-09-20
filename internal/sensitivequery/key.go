// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

// Package sensitivequery classifies URL query keys that commonly carry
// credentials. It deliberately operates on keys only; callers remain
// responsible for preserving or replacing values in their own representation.
package sensitivequery

import (
	"strings"
	"unicode/utf8"
)

const (
	maxKeyBytes     = 256
	maxDecodePasses = 3
)

var keys = map[string]struct{}{
	"access_token":         {},
	"api-key":              {},
	"api_key":              {},
	"apikey":               {},
	"auth":                 {},
	"authorization":        {},
	"client_secret":        {},
	"client_token":         {},
	"code":                 {},
	"credential":           {},
	"id_token":             {},
	"key":                  {},
	"passwd":               {},
	"password":             {},
	"pwd":                  {},
	"refresh_token":        {},
	"routing_key":          {},
	"secret":               {},
	"sig":                  {},
	"signature":            {},
	"token":                {},
	"webhook_token":        {},
	"x-amz-credential":     {},
	"x-amz-security-token": {},
	"x-amz-signature":      {},
	"x-goog-signature":     {},
}

// Classify reports whether raw resolves to a sensitive query key and whether
// its encoding is unambiguous. Percent-encoding is decoded a bounded number of
// times because logging inputs may have crossed multiple URL layers. Invalid,
// excessive, control-bearing, or separator-bearing encodings are ambiguous.
func Classify(raw string) (sensitive, valid bool) {
	canonical, valid := Canonical(raw)
	if !valid {
		return false, false
	}
	_, sensitive = keys[canonical]
	return sensitive, true
}

// Canonical returns the lowercase, bounded-percent-decoded form of raw.
func Canonical(raw string) (string, bool) {
	if raw == "" || len(raw) > maxKeyBytes || !utf8.ValidString(raw) {
		return "", false
	}
	value := raw
	for pass := 0; pass <= maxDecodePasses; pass++ {
		if strings.IndexByte(value, '%') < 0 {
			if !validDecodedKey(value) {
				return "", false
			}
			return strings.ToLower(value), true
		}
		if pass == maxDecodePasses {
			return "", false
		}
		decoded, ok := percentDecode(value)
		if !ok || !validDecodedKey(decoded) {
			return "", false
		}
		value = decoded
	}
	return "", false
}

func validDecodedKey(value string) bool {
	if value == "" || len(value) > maxKeyBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character >= 0x7f && character <= 0x9f {
			return false
		}
		switch character {
		case '&', ';', '=':
			return false
		}
	}
	return true
}

func percentDecode(value string) (string, bool) {
	decoded := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			decoded = append(decoded, value[i])
			continue
		}
		if i+2 >= len(value) {
			return "", false
		}
		high, highOK := fromHex(value[i+1])
		low, lowOK := fromHex(value[i+2])
		if !highOK || !lowOK {
			return "", false
		}
		decoded = append(decoded, high<<4|low)
		i += 2
	}
	return string(decoded), utf8.Valid(decoded)
}

func fromHex(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}
