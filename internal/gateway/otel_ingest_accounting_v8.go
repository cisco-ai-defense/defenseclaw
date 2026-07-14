// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"math"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type otlpInboundPrimaryDisposition string

const (
	otlpInboundImported               otlpInboundPrimaryDisposition = "imported"
	otlpInboundDerivedOnly            otlpInboundPrimaryDisposition = "derived_only"
	otlpInboundImportedAndDerived     otlpInboundPrimaryDisposition = "imported_and_derived"
	otlpInboundCollectionDisabled     otlpInboundPrimaryDisposition = "collection_disabled"
	otlpInboundSelfSuppressed         otlpInboundPrimaryDisposition = "self_suppressed"
	otlpInboundExactReplaySuppressed  otlpInboundPrimaryDisposition = "exact_replay_suppressed"
	otlpInboundHopLimit               otlpInboundPrimaryDisposition = "hop_limit"
	otlpInboundUnsupportedIdentity    otlpInboundPrimaryDisposition = "unsupported_identity"
	otlpInboundAmbiguousIdentity      otlpInboundPrimaryDisposition = "ambiguous_identity"
	otlpInboundInvalidMappedField     otlpInboundPrimaryDisposition = "invalid_mapped_field"
	otlpInboundInvalidRecord          otlpInboundPrimaryDisposition = "invalid_record"
	otlpInboundLocalPersistenceFailed otlpInboundPrimaryDisposition = "local_persistence_failed"
)

type otlpInboundDerivativeDisposition string

const (
	otlpInboundDerivativeRecorded           otlpInboundDerivativeDisposition = "recorded"
	otlpInboundDerivativeNoObservation      otlpInboundDerivativeDisposition = "no_observation"
	otlpInboundDerivativeCollectionDisabled otlpInboundDerivativeDisposition = "collection_disabled"
	otlpInboundDerivativeInvalidRecord      otlpInboundDerivativeDisposition = "invalid_derived_record"
	otlpInboundDerivativeDeliveryDegraded   otlpInboundDerivativeDisposition = "delivery_degraded"
)

type otlpInboundDropReasonCount struct {
	reason otlpInboundPrimaryDisposition
	count  int64
}

// otlpInboundBatchAccounting is a fixed-field accumulator: sender values can
// never create a new label/reason key or increase reason cardinality. Primary
// dispositions participate in the decoded-leaf equation; derivative target
// results are deliberately separate.
type otlpInboundBatchAccounting struct {
	decoded int64

	imported               int64
	derivedOnly            int64
	importedAndDerived     int64
	collectionDisabled     int64
	selfSuppressed         int64
	exactReplaySuppressed  int64
	hopLimit               int64
	unsupportedIdentity    int64
	ambiguousIdentity      int64
	invalidMappedField     int64
	invalidRecord          int64
	localPersistenceFailed int64

	derivativeRecorded           int64
	derivativeNoObservation      int64
	derivativeCollectionDisabled int64
	derivativeInvalidRecord      int64
	derivativeDeliveryDegraded   int64
	unknownFieldsDropped         int64
}

func (accounting *otlpInboundBatchAccounting) addUnknownFieldsDropped(count uint64) error {
	if accounting == nil || count > math.MaxInt64 || accounting.unknownFieldsDropped > math.MaxInt64-int64(count) {
		return errors.New("invalid OTLP unknown-field accounting")
	}
	accounting.unknownFieldsDropped += int64(count)
	return nil
}

func newOTLPInboundBatchAccounting(decoded int64) (otlpInboundBatchAccounting, error) {
	if decoded < 0 {
		return otlpInboundBatchAccounting{}, errors.New("invalid OTLP decoded leaf count")
	}
	return otlpInboundBatchAccounting{decoded: decoded}, nil
}

func (accounting *otlpInboundBatchAccounting) addPrimary(disposition otlpInboundPrimaryDisposition) error {
	if accounting == nil || accounting.primaryTotal() >= accounting.decoded {
		return errors.New("invalid OTLP primary accounting")
	}
	var count *int64
	switch disposition {
	case otlpInboundImported:
		count = &accounting.imported
	case otlpInboundDerivedOnly:
		count = &accounting.derivedOnly
	case otlpInboundImportedAndDerived:
		count = &accounting.importedAndDerived
	case otlpInboundCollectionDisabled:
		count = &accounting.collectionDisabled
	case otlpInboundSelfSuppressed:
		count = &accounting.selfSuppressed
	case otlpInboundExactReplaySuppressed:
		count = &accounting.exactReplaySuppressed
	case otlpInboundHopLimit:
		count = &accounting.hopLimit
	case otlpInboundUnsupportedIdentity:
		count = &accounting.unsupportedIdentity
	case otlpInboundAmbiguousIdentity:
		count = &accounting.ambiguousIdentity
	case otlpInboundInvalidMappedField:
		count = &accounting.invalidMappedField
	case otlpInboundInvalidRecord:
		count = &accounting.invalidRecord
	case otlpInboundLocalPersistenceFailed:
		count = &accounting.localPersistenceFailed
	default:
		return errors.New("unknown OTLP primary disposition")
	}
	(*count)++
	return nil
}

func (accounting *otlpInboundBatchAccounting) addDerivative(
	disposition otlpInboundDerivativeDisposition,
) error {
	if accounting == nil {
		return errors.New("invalid OTLP derivative accounting")
	}
	var count *int64
	switch disposition {
	case otlpInboundDerivativeRecorded:
		count = &accounting.derivativeRecorded
	case otlpInboundDerivativeNoObservation:
		count = &accounting.derivativeNoObservation
	case otlpInboundDerivativeCollectionDisabled:
		count = &accounting.derivativeCollectionDisabled
	case otlpInboundDerivativeInvalidRecord:
		count = &accounting.derivativeInvalidRecord
	case otlpInboundDerivativeDeliveryDegraded:
		count = &accounting.derivativeDeliveryDegraded
	default:
		return errors.New("unknown OTLP derivative disposition")
	}
	(*count)++
	return nil
}

func (accounting otlpInboundBatchAccounting) primaryTotal() int64 {
	return accounting.imported + accounting.derivedOnly + accounting.importedAndDerived +
		accounting.collectionDisabled + accounting.selfSuppressed + accounting.exactReplaySuppressed + accounting.hopLimit +
		accounting.unsupportedIdentity + accounting.ambiguousIdentity +
		accounting.invalidMappedField + accounting.invalidRecord + accounting.localPersistenceFailed
}

func (accounting otlpInboundBatchAccounting) valid() bool {
	return accounting.decoded >= 0 && accounting.primaryTotal() == accounting.decoded
}

func (accounting otlpInboundBatchAccounting) allSelfSuppressed() bool {
	return accounting.valid() && accounting.decoded > 0 && accounting.selfSuppressed == accounting.decoded
}

func (accounting otlpInboundBatchAccounting) outcome() (observability.Outcome, error) {
	if !accounting.valid() {
		return "", errors.New("incomplete OTLP primary accounting")
	}
	if accounting.permanentDropTotal() != 0 {
		return observability.OutcomePartial, nil
	}
	return observability.OutcomeCompleted, nil
}

func (accounting otlpInboundBatchAccounting) permanentDropTotal() int64 {
	return accounting.hopLimit + accounting.unsupportedIdentity + accounting.ambiguousIdentity +
		accounting.invalidMappedField + accounting.invalidRecord + accounting.localPersistenceFailed
}

// permanentDropReasons returns only nonzero reasons in the normative fixed
// order. Collection disablement and self suppression are intentional policy and
// loop dispositions, not dropped-record occurrences.
func (accounting otlpInboundBatchAccounting) permanentDropReasons() []otlpInboundDropReasonCount {
	ordered := [...]otlpInboundDropReasonCount{
		{reason: otlpInboundHopLimit, count: accounting.hopLimit},
		{reason: otlpInboundUnsupportedIdentity, count: accounting.unsupportedIdentity},
		{reason: otlpInboundAmbiguousIdentity, count: accounting.ambiguousIdentity},
		{reason: otlpInboundInvalidMappedField, count: accounting.invalidMappedField},
		{reason: otlpInboundInvalidRecord, count: accounting.invalidRecord},
		{reason: otlpInboundLocalPersistenceFailed, count: accounting.localPersistenceFailed},
	}
	result := make([]otlpInboundDropReasonCount, 0, len(ordered))
	for _, item := range ordered {
		if item.count > 0 {
			result = append(result, item)
		}
	}
	return result
}
