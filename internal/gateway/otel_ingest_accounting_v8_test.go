// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestOTLPInboundPartialBatchAccountingAndAck(t *testing.T) {
	primary := []otlpInboundPrimaryDisposition{
		otlpInboundImported,
		otlpInboundDerivedOnly,
		otlpInboundImportedAndDerived,
		otlpInboundCollectionDisabled,
		otlpInboundSelfSuppressed,
		otlpInboundHopLimit,
		otlpInboundUnsupportedIdentity,
		otlpInboundAmbiguousIdentity,
		otlpInboundInvalidMappedField,
		otlpInboundInvalidRecord,
		otlpInboundLocalPersistenceFailed,
	}
	accounting, err := newOTLPInboundBatchAccounting(int64(len(primary)))
	if err != nil {
		t.Fatal(err)
	}
	for _, disposition := range primary {
		if err := accounting.addPrimary(disposition); err != nil {
			t.Fatalf("add %s: %v", disposition, err)
		}
	}
	if !accounting.valid() || accounting.primaryTotal() != int64(len(primary)) {
		t.Fatalf("invalid complete accounting: %+v", accounting)
	}
	outcome, err := accounting.outcome()
	if err != nil || outcome != observability.OutcomePartial {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	wantReasons := []otlpInboundDropReasonCount{
		{reason: otlpInboundHopLimit, count: 1},
		{reason: otlpInboundUnsupportedIdentity, count: 1},
		{reason: otlpInboundAmbiguousIdentity, count: 1},
		{reason: otlpInboundInvalidMappedField, count: 1},
		{reason: otlpInboundInvalidRecord, count: 1},
		{reason: otlpInboundLocalPersistenceFailed, count: 1},
	}
	if reasons := accounting.permanentDropReasons(); !reflect.DeepEqual(reasons, wantReasons) {
		t.Fatalf("reasons=%+v want=%+v", reasons, wantReasons)
	}
}

func TestOTLPInboundBatchAccountingCompletedAndAllSelfTerminalCases(t *testing.T) {
	tests := []struct {
		name         string
		dispositions []otlpInboundPrimaryDisposition
		allSelf      bool
	}{
		{name: "empty"},
		{name: "successful and policy outcomes", dispositions: []otlpInboundPrimaryDisposition{
			otlpInboundImported, otlpInboundImportedAndDerived, otlpInboundDerivedOnly,
			otlpInboundCollectionDisabled, otlpInboundSelfSuppressed,
		}},
		{name: "all self", dispositions: []otlpInboundPrimaryDisposition{
			otlpInboundSelfSuppressed, otlpInboundSelfSuppressed,
		}, allSelf: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accounting, err := newOTLPInboundBatchAccounting(int64(len(test.dispositions)))
			if err != nil {
				t.Fatal(err)
			}
			for _, disposition := range test.dispositions {
				if err := accounting.addPrimary(disposition); err != nil {
					t.Fatal(err)
				}
			}
			outcome, err := accounting.outcome()
			if err != nil || outcome != observability.OutcomeCompleted ||
				accounting.allSelfSuppressed() != test.allSelf || len(accounting.permanentDropReasons()) != 0 {
				t.Fatalf("accounting=%+v outcome=%q allSelf=%t err=%v",
					accounting, outcome, accounting.allSelfSuppressed(), err)
			}
		})
	}
}

func TestOTLPInboundBatchAccountingRejectsMissingDuplicateAndUnknownDispositions(t *testing.T) {
	if _, err := newOTLPInboundBatchAccounting(-1); err == nil {
		t.Fatal("negative decoded count accepted")
	}
	accounting, err := newOTLPInboundBatchAccounting(1)
	if err != nil {
		t.Fatal(err)
	}
	if accounting.valid() {
		t.Fatal("missing primary disposition satisfied accounting equation")
	}
	if _, err := accounting.outcome(); err == nil {
		t.Fatal("incomplete accounting produced an outcome")
	}
	if err := accounting.addPrimary("unknown"); err == nil || accounting.primaryTotal() != 0 {
		t.Fatalf("unknown primary changed accounting: %+v err=%v", accounting, err)
	}
	if err := accounting.addPrimary(otlpInboundImported); err != nil {
		t.Fatal(err)
	}
	if err := accounting.addPrimary(otlpInboundImported); err == nil || accounting.primaryTotal() != 1 {
		t.Fatalf("second disposition accepted: %+v err=%v", accounting, err)
	}
	if err := (*otlpInboundBatchAccounting)(nil).addPrimary(otlpInboundImported); err == nil {
		t.Fatal("nil accounting accepted a primary disposition")
	}
	if err := accounting.addDerivative("unknown"); err == nil {
		t.Fatal("unknown derivative disposition accepted")
	}
}

func TestOTLPInboundBatchAccountingKeepsDerivativeTargetsOutsidePrimaryEquation(t *testing.T) {
	accounting, err := newOTLPInboundBatchAccounting(1)
	if err != nil {
		t.Fatal(err)
	}
	for _, disposition := range []otlpInboundDerivativeDisposition{
		otlpInboundDerivativeRecorded,
		otlpInboundDerivativeNoObservation,
		otlpInboundDerivativeCollectionDisabled,
		otlpInboundDerivativeInvalidRecord,
		otlpInboundDerivativeDeliveryDegraded,
	} {
		if err := accounting.addDerivative(disposition); err != nil {
			t.Fatal(err)
		}
	}
	if accounting.primaryTotal() != 0 || accounting.valid() {
		t.Fatalf("derivatives changed primary equation: %+v", accounting)
	}
	if err := accounting.addPrimary(otlpInboundDerivedOnly); err != nil {
		t.Fatal(err)
	}
	if !accounting.valid() || accounting.derivativeRecorded != 1 || accounting.derivativeNoObservation != 1 ||
		accounting.derivativeCollectionDisabled != 1 || accounting.derivativeInvalidRecord != 1 ||
		accounting.derivativeDeliveryDegraded != 1 {
		t.Fatalf("derivative counts=%+v", accounting)
	}
}
