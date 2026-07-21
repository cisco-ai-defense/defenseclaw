// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bytes"
	"testing"
)

func TestProjectionPolicyIsImmutableInProcessState(t *testing.T) {
	input := validRecordInput()
	input.projectionPolicy = RawProjectionPolicy()
	record, err := NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	if !record.ProjectionPolicy().IsRaw() || !record.Clone().ProjectionPolicy().IsRaw() {
		t.Fatal("record or clone lost its in-process projection policy")
	}
	encoded, err := record.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("projection_policy")) {
		t.Fatalf("projection policy escaped onto the canonical wire: %s", encoded)
	}
}

func TestImportedRecordCannotClaimLocalProjectionPolicy(t *testing.T) {
	provenance := validImportProvenance()
	input := validRecordInput()
	input.Provenance.Import = &provenance
	input.projectionPolicy = RawProjectionPolicy()
	if _, err := NewRecord(input); err == nil {
		t.Fatal("imported record claimed a raw local projection policy")
	}

	input.projectionPolicy = DefaultProjectionPolicy()
	record, err := NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	if !record.ProjectionPolicy().IsDefault() {
		t.Fatal("imported record did not retain the default projection policy")
	}
}
