// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

// RetentionPolicyComponentName is the generation-owned policy activation
// boundary around the process-stable retention controller.
const RetentionPolicyComponentName = "retention-policy"

type retentionPolicyFactory struct {
	controller *RetentionController
}

type retentionPolicyError struct{}

func (*retentionPolicyError) Error() string {
	return "observability retention policy initialization failed"
}

func (factory *retentionPolicyFactory) Name() string { return RetentionPolicyComponentName }

func (factory *retentionPolicyFactory) Prepare(
	ctx context.Context,
	input runtimegraph.BuildInput,
	acquisitions *runtimegraph.Acquisitions,
) (runtimegraph.Component, error) {
	if factory == nil || factory.controller == nil || ctx == nil || acquisitions == nil ||
		input.Config.Plan == nil {
		return nil, &retentionPolicyError{}
	}
	days := int64(input.Config.RetentionDays)
	if !validRetentionPolicyDays(days) {
		return nil, &retentionPolicyError{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reservation, err := factory.controller.reserveRetentionPolicy(days)
	if err != nil {
		return nil, &retentionPolicyError{}
	}
	if err := acquisitions.Register(
		"retention-policy-reservation",
		func(context.Context) error {
			reservation.release()
			return nil
		},
	); err != nil {
		reservation.release()
		return nil, &retentionPolicyError{}
	}
	if err := ctx.Err(); err != nil {
		reservation.release()
		return nil, err
	}
	return &retentionPolicyComponent{reservation: reservation}, nil
}

type retentionPolicyComponent struct {
	reservation *retentionPolicyReservation
	active      atomic.Bool
	closed      atomic.Bool
}

func (component *retentionPolicyComponent) Activate() {
	if component == nil || component.closed.Load() || component.reservation == nil {
		return
	}
	component.reservation.activate()
	component.active.Store(true)
}

func (component *retentionPolicyComponent) StopIntake(context.Context) error {
	if component == nil {
		return &retentionPolicyError{}
	}
	component.active.Store(false)
	return nil
}

func (component *retentionPolicyComponent) Drain(context.Context) error {
	if component == nil {
		return &retentionPolicyError{}
	}
	return nil
}

func (component *retentionPolicyComponent) Close(context.Context) error {
	if component == nil {
		return &retentionPolicyError{}
	}
	component.active.Store(false)
	component.closed.Store(true)
	if component.reservation != nil {
		component.reservation.release()
		component.reservation = nil
	}
	return nil
}

type retentionPolicyReservation struct {
	controller *RetentionController
	days       int64
	released   atomic.Bool
}

func (controller *RetentionController) reserveRetentionPolicy(
	days int64,
) (*retentionPolicyReservation, error) {
	if controller == nil || !validRetentionPolicyDays(days) {
		return nil, errors.New("observability retention policy reservation is invalid")
	}
	controller.lifecycleMu.Lock()
	if controller.stopped || !controller.runtimeOwned {
		controller.lifecycleMu.Unlock()
		return nil, errors.New("observability retention policy controller is unavailable")
	}
	return &retentionPolicyReservation{controller: controller, days: days}, nil
}

func (reservation *retentionPolicyReservation) activate() {
	if reservation == nil || reservation.controller == nil ||
		!reservation.released.CompareAndSwap(false, true) {
		return
	}
	// Prepare validated the exact same integer domain as audit retention. The
	// concrete reaper therefore cannot reject this update; activation remains
	// infallible and does no I/O or blocking work.
	_ = reservation.controller.applyPolicyLocked(reservation.days)
	reservation.controller.lifecycleMu.Unlock()
}

func (reservation *retentionPolicyReservation) release() {
	if reservation == nil || reservation.controller == nil ||
		!reservation.released.CompareAndSwap(false, true) {
		return
	}
	reservation.controller.lifecycleMu.Unlock()
}

func (controller *RetentionController) claimRuntimeOwnership() error {
	if controller == nil {
		return errors.New("observability retention controller is unavailable")
	}
	controller.lifecycleMu.Lock()
	defer controller.lifecycleMu.Unlock()
	if controller.runtimeOwned || controller.started || controller.stopped {
		return errors.New("observability retention controller lifecycle is unavailable")
	}
	controller.runtimeOwned = true
	return nil
}

func (controller *RetentionController) releaseRuntimeOwnership() {
	if controller == nil {
		return
	}
	controller.lifecycleMu.Lock()
	if !controller.started {
		controller.runtimeOwned = false
	}
	controller.lifecycleMu.Unlock()
}

func validRetentionPolicyDays(days int64) bool {
	const day = int64(24 * time.Hour)
	return days >= 0 && days <= math.MaxInt64/day
}

var _ runtimegraph.ComponentFactory = (*retentionPolicyFactory)(nil)
var _ runtimegraph.Component = (*retentionPolicyComponent)(nil)
