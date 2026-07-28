// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type hashV1GoldenFile struct {
	Contract      string               `json:"contract"`
	DefaultKeyHex string               `json:"default_key_hex"`
	DefaultKeyID  string               `json:"default_key_id"`
	Vectors       []hashV1GoldenVector `json:"vectors"`
	ErrorVectors  []hashV1ErrorVector  `json:"error_vectors"`
}

type hashV1GoldenVector struct {
	Name       string `json:"name"`
	FieldClass string `json:"field_class"`
	Value      string `json:"value"`
	Normalized string `json:"normalized"`
	KeyHex     string `json:"key_hex,omitempty"`
	KeyID      string `json:"key_id,omitempty"`
	Token      string `json:"token"`
}

type hashV1ErrorVector struct {
	Name       string          `json:"name"`
	FieldClass string          `json:"field_class"`
	Value      string          `json:"value"`
	KeyHex     string          `json:"key_hex,omitempty"`
	Error      HashV1ErrorCode `json:"error"`
}

type unicode13Manifest struct {
	SchemaVersion               int      `json:"schema_version"`
	UnicodeVersion              string   `json:"unicode_version"`
	Source                      string   `json:"source"`
	SourceSHA256                string   `json:"source_sha256"`
	RangeEncoding               string   `json:"range_encoding"`
	RangeDigestCanonicalization string   `json:"range_digest_canonicalization"`
	RangeSHA256                 string   `json:"range_sha256"`
	ScalarCount                 int      `json:"scalar_count"`
	Ranges                      []string `json:"ranges"`
}

func TestUnicode13GeneratedRangesMatchManifest(t *testing.T) {
	t.Parallel()
	encoded, err := os.ReadFile("../../../schemas/telemetry/v8/redaction/unicode-age-13.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest unicode13Manifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 1 || manifest.UnicodeVersion != "13.0.0" {
		t.Fatal("Unicode repertoire manifest has an unexpected contract version")
	}
	if manifest.Source != "https://www.unicode.org/Public/13.0.0/ucd/DerivedAge.txt" ||
		manifest.SourceSHA256 != "e779a443d3aa2a3166a15becaa2b737c922480e32c0453d5956093633555078f" {
		t.Fatal("Unicode repertoire manifest has an unexpected source identity")
	}
	if manifest.RangeEncoding != "inclusive uppercase six-digit hexadecimal START-END" ||
		manifest.RangeDigestCanonicalization != "each encoded range followed by LF" {
		t.Fatal("Unicode repertoire manifest has an unexpected range encoding")
	}
	if len(manifest.Ranges) != len(unicode13Ranges) {
		t.Fatalf("range count mismatch: got %d, want %d", len(unicode13Ranges), len(manifest.Ranges))
	}

	var canonical strings.Builder
	scalarCount := 0
	for index, encodedRange := range manifest.Ranges {
		firstText, lastText, ok := strings.Cut(encodedRange, "-")
		if !ok || len(firstText) != 6 || len(lastText) != 6 {
			t.Fatalf("invalid manifest range %q", encodedRange)
		}
		first, err := strconv.ParseInt(firstText, 16, 32)
		if err != nil {
			t.Fatal(err)
		}
		last, err := strconv.ParseInt(lastText, 16, 32)
		if err != nil {
			t.Fatal(err)
		}
		generated := unicode13Ranges[index]
		if generated.first != rune(first) || generated.last != rune(last) {
			t.Fatalf("generated range %d does not match manifest", index)
		}
		if encodedRange != fmt.Sprintf("%06X-%06X", generated.first, generated.last) {
			t.Fatalf("range %d is not canonically encoded", index)
		}
		if generated.first > generated.last ||
			(index > 0 && unicode13Ranges[index-1].last >= generated.first) ||
			(generated.first <= 0xDFFF && generated.last >= 0xD800) {
			t.Fatalf("range %d is invalid, overlapping, or contains a surrogate", index)
		}
		canonical.WriteString(encodedRange)
		canonical.WriteByte('\n')
		scalarCount += int(generated.last-generated.first) + 1
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(canonical.String())))
	if digest != manifest.RangeSHA256 || digest != unicode13RangesSHA256 {
		t.Fatal("Unicode repertoire range digest mismatch")
	}
	if scalarCount != manifest.ScalarCount {
		t.Fatalf("scalar count mismatch: got %d, want %d", scalarCount, manifest.ScalarCount)
	}
}

func TestHashV1GoldenVectors(t *testing.T) {
	t.Parallel()
	fixture := loadHashV1GoldenFile(t)
	if fixture.Contract != "hash-v1" {
		t.Fatal("golden fixture has an unexpected contract")
	}
	defaultKey := decodeTestKey(t, fixture.DefaultKeyHex)
	if got := hashV1KeyID(defaultKey); got != fixture.DefaultKeyID {
		t.Fatalf("default key ID mismatch: got %q, want %q", got, fixture.DefaultKeyID)
	}
	for _, vector := range fixture.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()
			key := defaultKey
			if vector.KeyHex != "" {
				key = decodeTestKey(t, vector.KeyHex)
			}
			if vector.KeyID != "" && hashV1KeyID(key) != vector.KeyID {
				t.Fatalf("rotated key ID mismatch: got %q, want %q", hashV1KeyID(key), vector.KeyID)
			}
			fieldClass := observability.FieldClass(vector.FieldClass)
			normalized, err := normalizeHashV1Value(vector.Value, fieldClass)
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if normalized != vector.Normalized {
				t.Fatalf("normalized value mismatch: got %q, want %q", normalized, vector.Normalized)
			}
			token, err := HashV1(vector.Value, fieldClass, key)
			if err != nil {
				t.Fatalf("HashV1: %v", err)
			}
			if token != vector.Token {
				t.Fatalf("token mismatch: got %q, want %q", token, vector.Token)
			}
			if strings.Contains(token, vector.Value) || strings.Contains(token, vector.Normalized) {
				t.Fatal("token disclosed original or normalized input")
			}
		})
	}
}

func TestHashV1SharedErrorVectors(t *testing.T) {
	t.Parallel()
	fixture := loadHashV1GoldenFile(t)
	defaultKey := decodeTestKey(t, fixture.DefaultKeyHex)
	for _, vector := range fixture.ErrorVectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()
			key := defaultKey
			if vector.KeyHex != "" {
				key = decodeTestKey(t, vector.KeyHex)
			}
			_, err := HashV1(vector.Value, observability.FieldClass(vector.FieldClass), key)
			if !IsHashV1Error(err, vector.Error) {
				t.Fatalf("got error %v, want %q", err, vector.Error)
			}
			if vector.Value != "" && strings.Contains(err.Error(), vector.Value) {
				t.Fatal("error disclosed rejected value")
			}
		})
	}
}

func TestHashV1SupportsEveryFieldClass(t *testing.T) {
	t.Parallel()
	key := make([]byte, hashV1KeySize)
	for _, fieldClass := range observability.FieldClasses() {
		if _, err := HashV1("value", fieldClass, key); err != nil {
			t.Fatalf("HashV1 class %q: %v", fieldClass, err)
		}
	}
}

func TestHashV1NonSchemePrefixUsesLexicalPathFallback(t *testing.T) {
	t.Parallel()
	key := make([]byte, hashV1KeySize)
	if _, err := HashV1("1https://example.test/%zz", observability.FieldClassPath, key); err != nil {
		t.Fatalf("lexical path fallback: %v", err)
	}
}

func TestHashV1TypedFailuresAreValueSafe(t *testing.T) {
	t.Parallel()
	validKey := []byte("0123456789abcdef0123456789abcdef")
	invalidUTF8 := string([]byte{0xff, 0xfe})
	tests := []struct {
		name       string
		value      string
		fieldClass observability.FieldClass
		key        []byte
		code       HashV1ErrorCode
		secret     string
	}{
		{"invalid-utf8", invalidUTF8, observability.FieldClassContent, validKey, HashV1ErrorInvalidUTF8, invalidUTF8},
		{"short-key", "private-value", observability.FieldClassContent, []byte("short-secret"), HashV1ErrorInvalidKey, "short-secret"},
		{"unsupported-class", "private-value", observability.FieldClass("unknown"), validKey, HashV1ErrorUnsupportedClass, "private-value"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := HashV1(test.value, test.fieldClass, test.key)
			if !IsHashV1Error(err, test.code) {
				t.Fatalf("got error %v", err)
			}
			if test.secret != "" && strings.Contains(err.Error(), test.secret) {
				t.Fatal("error disclosed caller material")
			}
		})
	}
}

func TestHashV1RotationChangesKeyIDAndDigest(t *testing.T) {
	t.Parallel()
	value := "/var/lib/defenseclaw/state.db"
	first, err := HashV1(value, observability.FieldClassPath, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashV1(value, observability.FieldClassPath, bytes.Repeat([]byte{1}, hashV1KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.Contains(first, "key=66687aadf862") || !strings.Contains(second, "key=72cd6e8422c4") {
		t.Fatal("rotation did not change both safe key identity and digest")
	}
}

func TestHashV1URIUserinfoNeverAppearsInToken(t *testing.T) {
	t.Parallel()
	key := make([]byte, hashV1KeySize)
	token, err := HashV1(
		"https://operator:super-secret@example.test/path",
		observability.FieldClassPath,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"operator", "super-secret", "example.test", "/path"} {
		if strings.Contains(token, forbidden) {
			t.Fatal("token disclosed URI input")
		}
	}
}

func loadHashV1GoldenFile(t *testing.T) hashV1GoldenFile {
	t.Helper()
	encoded, err := os.ReadFile("testdata/hash_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture hashV1GoldenFile
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func decodeTestKey(t *testing.T, encoded string) []byte {
	t.Helper()
	key, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
