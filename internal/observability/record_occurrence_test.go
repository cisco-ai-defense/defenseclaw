// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestPreflightRecordWithOccurrenceIsTheSecondBuild pins rel-1-0-6 GAP-0381:
// a generated record is built once, as the preflight record with the
// largest occurrence, and then takes the real occurrence. That must be the
// record a second build with the real occurrence made: the same data and
// the same bytes, for every signal, any valid record ID (up to
// MaxRecordIDBytes, backslashes, quotes, U+2028 and other non-ASCII text),
// any timestamp zone and precision, and bodies up to the encoded limit.
func TestPreflightRecordWithOccurrenceIsTheSecondBuild(t *testing.T) {
	ids := []string{"occurrence-1", "rec-model-001", strings.Repeat("\\", MaxRecordIDBytes), strings.Repeat("\"", MaxRecordIDBytes),
		"id line sep", strings.Repeat("é", MaxRecordIDBytes/2), "x"}
	times := []time.Time{
		time.Date(2026, 7, 3, 4, 3, 2, 1, time.FixedZone("offset", -5*3600)),
		time.Date(2026, 11, 2, 18, 0, 0, 0, time.UTC),
		time.Date(1970, 1, 1, 0, 0, 0, 1, time.UTC),
		time.Date(9999, 12, 31, 23, 59, 59, 999_999_999, time.UTC),
		time.Date(2026, 3, 8, 2, 30, 0, 123_000_000, time.FixedZone("plus", 13*3600+45*60)),
	}
	logIdentity := EventIdentity{Bucket: BucketComplianceActivity, Signal: SignalLogs, Name: "approval.resolved"}
	type build func(RecordInput) (Record, error)
	logContract := &testSchemaDerivedLogFamilyContract{identity: logIdentity, mandatory: true}
	cases := []struct {
		name  string
		input func() RecordInput
		build build
	}{
		{"schema-derived log", func() RecordInput {
			input := validRecordInput()
			input.Identity, input.Outcome, input.FieldClasses = logIdentity, OutcomeApproved, nil
			input.Body = map[string]any{"message": "a \\ \"quoted\"   line <tag> & é", "count": 2, "nested": map[string]any{"list": []any{1, "two", nil}}}
			return input
		}, func(input RecordInput) (Record, error) { return newSchemaDerivedLogRecord(input, logContract) }},
		{"schema-derived metric", func() RecordInput {
			input := validMetricRecordInput()
			input.FieldClasses = nil
			return input
		}, newSchemaDerivedRecord},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, id := range ids {
				for _, at := range times {
					assertOccurrenceMatchesSecondBuild(t, tc.input(), tc.build, at, id)
				}
			}
		})
	}
	// At the size limit: the largest body the preflight record takes, found
	// by bisection, and its neighbours. Whenever the preflight record fits,
	// the real record is the same record with its occurrence.
	t.Run("log body at the size limit", func(t *testing.T) {
		base := cases[0].input()
		withBody := func(n int) RecordInput {
			input := base
			input.Body = map[string]any{"message": strings.Repeat("m", n)}
			return input
		}
		fits := func(n int) bool {
			worst := withBody(n)
			worst.Timestamp = time.Date(9999, 12, 31, 23, 59, 59, 999_999_999, time.UTC)
			worst.RecordID = strings.Repeat("\\", MaxRecordIDBytes)
			_, err := cases[0].build(worst)
			return err == nil
		}
		low, high := 0, MaxCanonicalRecordBytes+1
		if !fits(low) || fits(high) {
			t.Fatal("bisection bounds do not bracket the limit")
		}
		for high-low > 1 {
			mid := (low + high) / 2
			if fits(mid) {
				low = mid
			} else {
				high = mid
			}
		}
		for _, n := range []int{low - 1, low, high} {
			fit := assertOccurrenceMatchesSecondBuild(t, withBody(n), cases[0].build, times[1], "occurrence-1")
			if fit != (n <= low) {
				t.Fatalf("body of %d bytes (largest that fits %d): preflight fit = %v", n, low, fit)
			}
		}
	})
}

// assertOccurrenceMatchesSecondBuild reports whether the preflight record
// was built; when it was, the real build must succeed and equal it with the
// real occurrence.
func assertOccurrenceMatchesSecondBuild(t *testing.T, input RecordInput, build func(RecordInput) (Record, error), at time.Time, id string) bool {
	t.Helper()
	worst := input
	worst.Timestamp = time.Date(9999, 12, 31, 23, 59, 59, 999_999_999, time.UTC)
	worst.RecordID = strings.Repeat("\\", MaxRecordIDBytes)
	checked, err := build(worst)
	if err != nil {
		return false
	}
	real := input
	real.Timestamp, real.RecordID = at, id
	want, err := build(real)
	if err != nil {
		t.Fatalf("id %q at %v: the preflight record fit but the real build failed: %v", id, at, err)
	}
	got := checked.withOccurrence(at, id)
	if !reflect.DeepEqual(got.data, want.data) {
		t.Fatalf("id %q at %v: record data differs:\n got %#v\nwant %#v", id, at, got.data, want.data)
	}
	gotBytes, gotErr := got.Bytes()
	wantBytes, wantErr := want.Bytes()
	if gotErr != nil || wantErr != nil || !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("id %q at %v: encoded record differs (%v, %v)", id, at, gotErr, wantErr)
	}
	return true
}
