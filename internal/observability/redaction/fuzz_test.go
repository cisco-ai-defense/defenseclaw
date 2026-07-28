// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func FuzzEngineDynamicBodyTraversal(f *testing.F) {
	for _, seed := range []struct {
		encoded []byte
		profile byte
	}{
		{[]byte(`{}`), 0},
		{[]byte(`{"a":"person@example.test","nested":{"~key/part":["secret",null,{}]}}`), 1},
		{[]byte(`{"array":[[],{"credential":"sk-test-12345678901234567890"}]}`), 2},
		{[]byte(`{"unicode":"é/ /😀"}`), 3},
	} {
		f.Add(seed.encoded, seed.profile)
	}

	f.Fuzz(func(t *testing.T, encoded []byte, profileIndex byte) {
		if len(encoded) > 64*1024 {
			return
		}
		value, err := observability.ParseValue(encoded)
		if err != nil {
			return
		}
		object, err := value.Object()
		if err != nil {
			t.Fatalf("parsed value did not expose an object: %v", err)
		}
		classes := make(map[string]observability.FieldClass)
		for _, pointer := range leafPointers(object) {
			classes[pointer] = observability.FieldClassContent
		}
		record := newTestRecord(t, observability.SignalLogs, object, classes)
		before, err := record.Bytes()
		if err != nil {
			t.Fatalf("record serialization failed: %v", err)
		}

		profiles := []ProfileName{ProfileNone, ProfileSensitive, ProfileContent, ProfileStrict}
		profile, ok := BuiltInProfile(profiles[int(profileIndex)%len(profiles)])
		if !ok {
			t.Fatal("built-in profile disappeared")
		}
		engine := newTestEngine(t)
		first, firstReport, err := engine.Project(record, profile)
		if err != nil {
			t.Fatalf("valid classified object failed projection: %v", err)
		}
		second, secondReport, err := engine.Project(record, profile)
		if err != nil {
			t.Fatalf("repeat projection failed: %v", err)
		}
		firstBytes, err := first.Bytes()
		if err != nil {
			t.Fatalf("projection serialization failed: %v", err)
		}
		secondBytes, err := second.Bytes()
		if err != nil {
			t.Fatalf("repeat projection serialization failed: %v", err)
		}
		if !bytes.Equal(firstBytes, secondBytes) ||
			!reflect.DeepEqual(firstReport.Metadata(), secondReport.Metadata()) ||
			!reflect.DeepEqual(firstReport.Entries(), secondReport.Entries()) {
			t.Fatal("projection was not deterministic")
		}
		if after, _ := record.Bytes(); !bytes.Equal(before, after) {
			t.Fatal("projection mutated the canonical record")
		}
		payload := first.Payload()
		if _, err := observability.ParseValue(payload.Bytes()); err != nil {
			t.Fatalf("projected payload is not canonical: %v", err)
		}
		if profile.Name() == ProfileNone && !bytes.Equal(payload.Bytes(), value.Bytes()) {
			t.Fatal("none profile changed a canonical payload")
		}
	})
}

func FuzzRedactionUnicodeAndMalformedEncodings(f *testing.F) {
	for _, seed := range []struct {
		input []byte
		group byte
	}{
		{[]byte("person@example.test"), 0},
		{[]byte("éperson@example.test界"), 0},
		{[]byte("token=sk-test-12345678901234567890"), 1},
		{[]byte("https://example.test/?token=%zz"), 2},
		{[]byte("e\u0301 and 😀"), 0},
		{[]byte{0xff, 0xfe, 'x'}, 1},
	} {
		f.Add(seed.input, seed.group)
	}

	f.Fuzz(func(t *testing.T, input []byte, groupIndex byte) {
		if len(input) > MaxScannedStringBytes+1 {
			return
		}
		groups := []DetectorGroup{DetectorGroupPII, DetectorGroupCredentials, DetectorGroupSecrets}
		group := groups[int(groupIndex)%len(groups)]
		key := bytes.Repeat([]byte{0x42}, 32)
		first, firstErr := DetectAndRedact(
			string(input), observability.FieldClassContent, []DetectorGroup{group}, key, NewRecordMatchBudget(),
		)
		second, secondErr := DetectAndRedact(
			string(input), observability.FieldClassContent, []DetectorGroup{group}, key, NewRecordMatchBudget(),
		)
		if (firstErr == nil) != (secondErr == nil) || !reflect.DeepEqual(first, second) {
			t.Fatal("detector result was not deterministic")
		}
		if firstErr != nil {
			if first.Failure == "" || first.Value == string(input) || !utf8.ValidString(first.Value) {
				t.Fatalf("detector failure did not fail closed: failure=%q", first.Failure)
			}
		} else {
			if !utf8.ValidString(first.Value) {
				t.Fatal("detector produced invalid UTF-8")
			}
			previousEnd := 0
			for _, match := range first.Matches {
				if match.Start < previousEnd || match.Start < 0 || match.End <= match.Start || match.End > len(input) ||
					!utf8.Valid(input[:match.Start]) || !utf8.Valid(input[:match.End]) {
					t.Fatalf("invalid match boundary: %+v after %d", match, previousEnd)
				}
				previousEnd = match.End
			}
		}

		firstHash, firstHashErr := HashV1(string(input), observability.FieldClassContent, key)
		secondHash, secondHashErr := HashV1(string(input), observability.FieldClassContent, key)
		if (firstHashErr == nil) != (secondHashErr == nil) || firstHash != secondHash {
			t.Fatal("hash-v1 result was not deterministic")
		}
		if firstHashErr != nil {
			var safe *HashV1Error
			if !errors.As(firstHashErr, &safe) || safe.Code == "" {
				t.Fatalf("hash-v1 returned unsafe error type %T", firstHashErr)
			}
		} else if firstHash == "" || !utf8.ValidString(firstHash) {
			t.Fatal("hash-v1 returned an invalid token")
		}
	})
}
