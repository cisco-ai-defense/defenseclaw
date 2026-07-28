// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"errors"
	"time"
)

// ErrorCode is a content-free construction or payload failure identity.
type ErrorCode string

const (
	ErrorInvalidConfig   ErrorCode = "invalid_config"
	ErrorInvalidContext  ErrorCode = "invalid_context"
	ErrorInvalidPayload  ErrorCode = "invalid_payload"
	ErrorInvalidIdentity ErrorCode = "invalid_identity"
)

// Error never contains an endpoint, header, projected value, or adapter error.
type Error struct{ code ErrorCode }

func (err *Error) Error() string {
	if err == nil {
		return "observability delivery rejected"
	}
	return "observability delivery rejected: " + string(err.code)
}
func (err *Error) Code() ErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

func newError(code ErrorCode) error { return &Error{code: code} }

// IsError reports whether err has the requested bounded code.
func IsError(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.code == code
}

// DeliveryOutcome is the adapter's complete disposition. Only transient and
// ambiguous outcomes are eligible for bounded retry. Ambiguous acknowledges
// that the remote side may have committed before its acknowledgement was lost.
// Partial is a terminal acknowledged split: its exact delivered/rejected item
// counts prevent an accepted subset from being retried.
type DeliveryOutcome string

const (
	OutcomeDelivered        DeliveryOutcome = "delivered"
	OutcomePartial          DeliveryOutcome = "partial"
	OutcomeTransient        DeliveryOutcome = "transient"
	OutcomeAuthentication   DeliveryOutcome = "authentication"
	OutcomePermanentPayload DeliveryOutcome = "permanent_payload"
	OutcomeUnsafeEndpoint   DeliveryOutcome = "unsafe_endpoint"
	OutcomeAmbiguous        DeliveryOutcome = "ambiguous"
)

// DeliveryResult contains no free-form adapter diagnostics. DeliveredItems and
// RejectedItems must both be positive, non-overflowing, and sum to Batch.Len
// only when Outcome is OutcomePartial. They must be zero for every other
// outcome. The dispatcher rejects malformed adapter results without retrying or
// over-reporting remote delivery.
type DeliveryResult struct {
	Outcome        DeliveryOutcome
	DeliveredItems int
	RejectedItems  int
}

// BatchItem is an immutable adapter view of one queued projection.
type BatchItem struct{ payload Payload }

func (item BatchItem) Bytes() []byte             { return item.payload.Bytes() }
func (item BatchItem) Size() int                 { return item.payload.Size() }
func (item BatchItem) Identity() RoutingIdentity { return item.payload.Identity() }
func (item BatchItem) RecordID() string          { return item.payload.identity.RecordID }
func (item BatchItem) OriginDestination() string { return item.payload.identity.OriginDestination }

// Batch is the bounded adapter input for one attempt. Items returns value views
// whose byte accessors still copy; a retry reuses the same private Batch.
type Batch struct {
	destination string
	items       []BatchItem
	encodedSize int
}

func (batch Batch) Destination() string { return batch.destination }
func (batch Batch) Len() int            { return len(batch.items) }
func (batch Batch) EncodedSize() int    { return batch.encodedSize }
func (batch Batch) Items() []BatchItem  { return append([]BatchItem(nil), batch.items...) }

// Adapter estimates the complete encoded request before a Batch is built and
// returns a closed delivery disposition. EncodedSize must account for every
// wrapper and separator byte and must return ok=false on arithmetic overflow or
// an unsupported shape. Deliver must honor context cancellation.
type Adapter interface {
	EncodedSize(projectedSizes []int) (size int, ok bool)
	Deliver(context.Context, Batch) DeliveryResult
}

// DelimitedEncodedSize is a safe estimator for a prefix, suffix, and fixed
// separator around exact projected bytes. It allocates no encoded request.
func DelimitedEncodedSize(projectedSizes []int, prefix, separator, suffix int) (int, bool) {
	if prefix < 0 || separator < 0 || suffix < 0 {
		return 0, false
	}
	total := prefix
	if total > intMax-suffix {
		return 0, false
	}
	total += suffix
	for index, size := range projectedSizes {
		if size < 0 || total > intMax-size {
			return 0, false
		}
		total += size
		if index > 0 {
			if total > intMax-separator {
				return 0, false
			}
			total += separator
		}
	}
	return total, true
}

const intMax = int(^uint(0) >> 1)

// EnqueueDisposition and EnqueueReason are a closed, content-free result.
type EnqueueDisposition string
type EnqueueReason string

const (
	EnqueueAccepted EnqueueDisposition = "accepted"
	EnqueueDropped  EnqueueDisposition = "dropped"
	EnqueueRejected EnqueueDisposition = "rejected"

	ReasonNone              EnqueueReason = "none"
	ReasonCountLimit        EnqueueReason = "count_limit"
	ReasonByteLimit         EnqueueReason = "byte_limit"
	ReasonCountAndByteLimit EnqueueReason = "count_and_byte_limit"
	ReasonInactive          EnqueueReason = "inactive"
	ReasonIntakeStopped     EnqueueReason = "intake_stopped"
	ReasonOriginLoop        EnqueueReason = "origin_loop"
	ReasonInvalidPayload    EnqueueReason = "invalid_payload"
)

type EnqueueResult struct {
	Disposition EnqueueDisposition
	Reason      EnqueueReason
}

func (result EnqueueResult) Accepted() bool { return result.Disposition == EnqueueAccepted }

// HealthState is the exact seven-state destination vocabulary.
type HealthState string

const (
	HealthDisabled     HealthState = "disabled"
	HealthInitializing HealthState = "initializing"
	HealthHealthy      HealthState = "healthy"
	HealthDegraded     HealthState = "degraded"
	HealthFailing      HealthState = "failing"
	HealthDraining     HealthState = "draining"
	HealthStopped      HealthState = "stopped"
)

// HealthReason is deliberately bounded and contains no endpoint or payload.
type HealthReason string

const (
	HealthReasonActivated      HealthReason = "activated"
	HealthReasonQueueFull      HealthReason = "queue_full"
	HealthReasonRetryable      HealthReason = "retryable_delivery"
	HealthReasonPartial        HealthReason = "partial_delivery"
	HealthReasonDeliveryFailed HealthReason = "delivery_failed"
	HealthReasonRecovered      HealthReason = "delivery_recovered"
	HealthReasonIntakeStopped  HealthReason = "intake_stopped"
	HealthReasonClosed         HealthReason = "closed"
	HealthReasonOriginLoop     HealthReason = "origin_loop"
)

// Counters are monotonic record counters, not request counters.
type Counters struct {
	Accepted  uint64
	Delivered uint64
	Retried   uint64
	Dropped   uint64
	Rejected  uint64
	// Failed counts failed delivery operations, not affected records. It is
	// therefore the monotonic source for exporter-error telemetry even when one
	// failed batch contains many records or later succeeds after a retry.
	Failed uint64
}

// QueueSnapshot is an immutable, content-free view of one generation-owned
// delivery queue. Items and Bytes include the in-flight batch because those
// projections remain charged until they reach a terminal disposition.
type QueueSnapshot struct {
	Items         int
	Bytes         int
	InFlightItems int
	InFlightBytes int
	MaxItems      int
	MaxBytes      int
}

// HealthSnapshot is the narrow read-only health contract shared by the log,
// trace, metric, and pull-reader generation components. Queue is nil for a
// signal that has no DefenseClaw-owned queue. Reason is a closed token owned by
// the source package; it never contains an error, endpoint, header, or payload.
type HealthSnapshot struct {
	Destination string
	Generation  uint64
	Signal      string
	State       HealthState
	Reason      string
	Queue       *QueueSnapshot
	Counters    Counters
	LastSuccess time.Time
	LastFailure time.Time
}

// SnapshotSource exposes no transport operation or mutable queue handle.
// Implementations return a detached value on every call.
type SnapshotSource interface {
	DeliveryHealthSnapshot() HealthSnapshot
}

// HealthTransition is safe for mandatory platform-health reporting. It carries
// only bounded destination identity, closed state/reason values, and counters.
type HealthTransition struct {
	Destination string
	Generation  uint64
	Previous    HealthState
	Current     HealthState
	Reason      HealthReason
	Counters    Counters
	OccurredAt  time.Time
	sequence    uint64
}

type Observer interface{ Observe(HealthTransition) }

type ObserverFunc func(HealthTransition)

func (function ObserverFunc) Observe(transition HealthTransition) { function(transition) }

// RetryPolicy bounds every retry sequence. MaxAttempts includes the initial
// attempt. Jitter may replace a computed delay but its result is clamped into
// [0, MaxBackoff]. A nil Jitter uses bounded process randomness.
type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Jitter         func(time.Duration, int) time.Duration
}

// Config is generation-owned and immutable after NewDispatcher returns.
type Config struct {
	Destination      string
	Generation       uint64
	Signal           string
	Enabled          bool
	MaxQueueItems    int
	MaxQueueBytes    int
	MaxBatchItems    int
	MaxBatchBytes    int
	ScheduledDelay   time.Duration
	AttemptTimeout   time.Duration
	Retry            RetryPolicy
	Observer         Observer
	ObserverInterval time.Duration
}
