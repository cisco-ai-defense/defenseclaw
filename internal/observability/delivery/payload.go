// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package delivery owns the bounded, generation-local handoff from immutable
// observability projections to optional destination adapters.
package delivery

import (
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// MaxPayloadBytes is the largest complete projected record accepted by the
// common delivery layer. It includes the canonical record ceiling and the
// projection metadata allowance. Destination wrappers are accounted for by
// Adapter.EncodedSize and are never retained in Payload.
const MaxPayloadBytes = observability.MaxCanonicalRecordBytes + 4*1024

// RoutingIdentity is the complete non-content identity retained beside a
// projected payload. OriginDestination prevents a receiver from exporting a
// record back to the destination from which it was ingested.
type RoutingIdentity struct {
	RecordID          string
	Bucket            string
	Signal            string
	EventName         string
	OriginDestination string
}

// Payload is an immutable projected encoding. Its byte slice is never exposed;
// every accessor returns a copy so adapters cannot mutate a queued retry.
type Payload struct {
	encoded  []byte
	identity RoutingIdentity
}

// NewPayload validates bounded routing identity and snapshots projected bytes.
// It deliberately does not parse, redact, re-encode, or otherwise interpret the
// already-projected representation.
func NewPayload(encoded []byte, identity RoutingIdentity) (Payload, error) {
	if len(encoded) == 0 || len(encoded) > MaxPayloadBytes {
		return Payload{}, newError(ErrorInvalidPayload)
	}
	if !validRecordID(identity.RecordID) ||
		!observability.IsRegisteredEventIdentity(observability.EventIdentity{
			Bucket: observability.Bucket(identity.Bucket),
			Signal: observability.Signal(identity.Signal),
			Name:   observability.EventName(identity.EventName),
		}) ||
		(identity.OriginDestination != "" && !observability.IsStableToken(identity.OriginDestination)) {
		return Payload{}, newError(ErrorInvalidIdentity)
	}
	return Payload{
		encoded:  append([]byte(nil), encoded...),
		identity: identity,
	}, nil
}

func validRecordID(value string) bool {
	if value == "" || len(value) > observability.MaxRecordIDBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// Bytes returns an independent copy of the exact projected encoding.
func (payload Payload) Bytes() []byte { return append([]byte(nil), payload.encoded...) }

// Size returns the exact number of projected bytes charged to the queue.
func (payload Payload) Size() int { return len(payload.encoded) }

// Identity returns the bounded routing identity by value.
func (payload Payload) Identity() RoutingIdentity { return payload.identity }

func (payload Payload) valid() bool {
	return len(payload.encoded) > 0 && len(payload.encoded) <= MaxPayloadBytes &&
		validRecordID(payload.identity.RecordID)
}
