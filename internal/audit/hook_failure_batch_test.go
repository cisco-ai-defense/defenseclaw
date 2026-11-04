// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

type hookFailurePartialEmitter struct {
	outcomes []RuntimeV8EmitOutcome
	err      error
}

func (emitter hookFailurePartialEmitter) EmitRuntimeV8(
	context.Context, router.Metadata, RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	return RuntimeV8EmitOutcome{}, errors.New("single record path was not selected")
}

func (emitter hookFailurePartialEmitter) EmitRuntimeV8AtomicLogBatch(
	context.Context, []RuntimeV8LogOperation,
) ([]RuntimeV8EmitOutcome, error) {
	return emitter.outcomes, emitter.err
}

func TestHookFailureBatchAdvancesOnlySettledPrefix(t *testing.T) {
	rows := []HookFailureAuditRow{
		{Action: string(ActionGuardrailBlock), Target: "claudecode:PreToolUse", Severity: "MEDIUM"},
		{Action: string(ActionGuardrailBlock), Target: "claudecode:PreToolUse", Severity: "MEDIUM"},
	}
	persisted := RuntimeV8EmitOutcome{Admission: router.AdmissionOrdinary, LocalPersisted: true}
	notPersisted := RuntimeV8EmitOutcome{Admission: router.AdmissionOrdinary}
	interrupted := errors.New("interrupted batch")
	for _, tc := range []struct {
		name     string
		outcomes []RuntimeV8EmitOutcome
		err      error
		want     int
	}{
		{"committed prefix", []RuntimeV8EmitOutcome{persisted}, interrupted, 1},
		{"uncommitted group", []RuntimeV8EmitOutcome{notPersisted, notPersisted}, interrupted, 0},
		{"completed group", []RuntimeV8EmitOutcome{persisted, persisted}, nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := NewLogger(nil)
			logger.SetRuntimeV8Emitter(hookFailurePartialEmitter{outcomes: tc.outcomes, err: tc.err})
			settled, err := logger.LogHookFailureRowsAtomic(context.Background(), rows)
			if settled != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("settled=%d error=%v, want %d and %v", settled, err, tc.want, tc.err)
			}
		})
	}
}
