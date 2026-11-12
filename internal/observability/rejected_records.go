// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"errors"
	"sort"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// The v8 schema gate (the generated family builders) refuses a record whose
// fields break its family contract, and the producer then counts it as a
// build failure (pipeline.ErrorRecordBuild). With
// observability.local.keep_rejected_records the gateway also keeps a redacted
// copy of each refused record in the local audit store, so an operator can see
// which records were refused and why (#1442). This file is the capture side:
// it copies the refused input, bounded, and hands it to the installed sink.
// The sink (observability/runtime) redacts and writes it off the producer's
// path. With no sink installed, the capture is one atomic load on the failure
// path and nothing on an accepted record.

const (
	// RejectedRecordMaxFieldBytes bounds one captured field value. A larger
	// value is left out and its key listed in OmittedFields.
	RejectedRecordMaxFieldBytes = 16 << 10
	// RejectedRecordMaxCaptureBytes bounds the values captured from one
	// refused record; the fields past it are left out and listed.
	RejectedRecordMaxCaptureBytes = 64 << 10
	// rejectedRecordMaxOmittedFields bounds the list of left-out keys.
	rejectedRecordMaxOmittedFields = 64
	rejectedRecordMaxTokenBytes    = 128
)

// RejectedRecord is one record the v8 schema gate refused, as captured before
// redaction. Body holds the producer's field values that could be encoded,
// keyed by their schema key, and FieldClasses classifies every leaf of Body
// with the field class of its schema field, so the sink redacts it with the
// same profile modes as the projection boundary. Body never leaves the
// process unredacted.
type RejectedRecord struct {
	ObservedAt          time.Time
	Signal              Signal
	Bucket              Bucket
	EventName           EventName
	Family              string
	FamilySchemaVersion uint32
	Source              Source
	Connector           string
	Reason              FamilyBuildErrorCode
	// Field is the schema key of the field that failed, "" when the failure
	// was not about one field.
	Field        string
	Body         map[string]any
	FieldClasses map[string]FieldClass
	// OmittedFields are keys whose values were not captured: unknown to the
	// family, not encodable, or over the size bounds. Sorted, bounded.
	OmittedFields []string
}

// ErrorText is the bounded, value-free validation error of the record: the
// gate's error and the failing field's schema key.
func (record RejectedRecord) ErrorText() string {
	text := (&FamilyBuildError{code: record.Reason}).Error()
	if record.Field != "" {
		text += "; field " + record.Field
	}
	return text
}

// RejectedRecordSink receives refused records. OfferRejectedRecord must not
// block or do I/O: it queues the record, or drops and counts it.
type RejectedRecordSink interface {
	OfferRejectedRecord(RejectedRecord)
}

type rejectedRecordSinkSlot struct{ sink RejectedRecordSink }

var rejectedRecordSink atomic.Pointer[rejectedRecordSinkSlot]

// InstallRejectedRecordSink makes sink the receiver of refused records and
// returns the function that removes it again. The remove function removes
// only this installation: if a later generation installed its own sink in
// between, that one stays. A nil sink installs nothing.
func InstallRejectedRecordSink(sink RejectedRecordSink) (uninstall func()) {
	if nilInterface(sink) {
		return func() {}
	}
	slot := &rejectedRecordSinkSlot{sink: sink}
	rejectedRecordSink.Store(slot)
	return func() { rejectedRecordSink.CompareAndSwap(slot, nil) }
}

// ClearRejectedRecordSink removes whatever sink is installed. A generation
// with the store off calls it when it activates: the generation it replaces
// retires in the background, and its sink must not keep taking records after
// the key was turned off.
func ClearRejectedRecordSink() { rejectedRecordSink.Store(nil) }

// RejectedRecordSinkInstalled is true while the opt-in store is on.
func RejectedRecordSinkInstalled() bool { return rejectedRecordSink.Load() != nil }

// offerRejectedFamilyRecord copies one refused generated record and offers it
// to the installed sink. A misuse of the builder itself (nil builder, nil
// clock) carries no record and is not offered.
func offerRejectedFamilyRecord(
	contract familyDescriptorContract,
	signal Signal,
	envelope FamilyEnvelopeInput,
	values familyFieldValues,
	err error,
) {
	slot := rejectedRecordSink.Load()
	if slot == nil || err == nil {
		return
	}
	var buildError *FamilyBuildError
	if !errors.As(err, &buildError) || buildError.code == FamilyBuildInvalidDependency {
		return
	}
	record := RejectedRecord{
		ObservedAt:          time.Now().UTC(),
		Signal:              signal,
		Bucket:              contract.identity.Bucket,
		EventName:           contract.identity.Name,
		Family:              boundedRejectedToken(contract.id),
		FamilySchemaVersion: contract.familySchemaVersion,
		Source:              Source(boundedRejectedToken(string(envelope.Source))),
		Connector:           boundedRejectedToken(envelope.Connector),
		Reason:              buildError.code,
		Field:               boundedRejectedKey(buildError.field),
	}
	if observed, present := envelope.ObservedAt.Get(); present && !observed.IsZero() {
		record.ObservedAt = observed.UTC()
	}
	record.Body, record.FieldClasses, record.OmittedFields = captureRejectedFamilyValues(contract.fields, values)
	slot.sink.OfferRejectedRecord(record)
}

// captureRejectedFamilyValues copies the present values whose key the family
// declares, canonicalized and classified with the declared field class. The
// rest is listed by key only.
func captureRejectedFamilyValues(
	descriptors []familyFieldDescriptor,
	values familyFieldValues,
) (map[string]any, map[string]FieldClass, []string) {
	declared := make(map[string]FieldClass, len(descriptors))
	for _, descriptor := range descriptors {
		declared[descriptor.key] = descriptor.fieldClass
	}
	body := make(map[string]any)
	classes := make(map[string]FieldClass)
	omitted := make(map[string]struct{})
	captured := 0
	for _, value := range values {
		if !value.present {
			continue
		}
		class, known := declared[value.key]
		if !known || !IsFieldClass(class) {
			omitted[boundedRejectedKey(value.key)] = struct{}{}
			continue
		}
		if _, duplicate := body[value.key]; duplicate {
			continue
		}
		canonical, err := canonicalFamilyJSONValue(value.value)
		if err != nil {
			omitted[value.key] = struct{}{}
			continue
		}
		size := rejectedValueBytes(canonical)
		if size > RejectedRecordMaxFieldBytes || captured+size > RejectedRecordMaxCaptureBytes {
			omitted[value.key] = struct{}{}
			continue
		}
		captured += size
		body[value.key] = canonical
		addFamilyLeafClasses(classes, "/"+encodeJSONPointerToken(value.key), canonical, class)
	}
	delete(omitted, "")
	list := make([]string, 0, len(omitted))
	for key := range omitted {
		list = append(list, key)
	}
	sort.Strings(list)
	if len(list) > rejectedRecordMaxOmittedFields {
		list = list[:rejectedRecordMaxOmittedFields]
	}
	return body, classes, list
}

// rejectedValueBytes approximates the encoded size of a canonical value: its
// string bytes plus a small charge per scalar and container.
func rejectedValueBytes(value any) int {
	switch typed := value.(type) {
	case string:
		return len(typed) + 2
	case map[string]any:
		total := 2
		for key, child := range typed {
			total += len(key) + 3 + rejectedValueBytes(child)
		}
		return total
	case []any:
		total := 2
		for _, child := range typed {
			total += 1 + rejectedValueBytes(child)
		}
		return total
	case []string:
		total := 2
		for _, child := range typed {
			total += len(child) + 3
		}
		return total
	default:
		return 24
	}
}

// boundedRejectedToken keeps a stable token as it is and drops anything else:
// these columns are filters, not evidence.
func boundedRejectedToken(value string) string {
	if len(value) > rejectedRecordMaxTokenBytes || !IsStableToken(value) {
		return ""
	}
	return value
}

// boundedRejectedKey keeps a schema key that is valid UTF-8 and short.
func boundedRejectedKey(key string) string {
	if !utf8.ValidString(key) || len(key) > MaxCanonicalValueBytes || len(key) > 256 {
		return ""
	}
	return key
}
