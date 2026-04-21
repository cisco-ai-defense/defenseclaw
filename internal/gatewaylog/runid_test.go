// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gatewaylog

import (
	"testing"
)

// TestProcessRunID_AtomicOverridesEnv pins the precedence contract
// documented on runID: the atomic slot installed at sidecar boot via
// SetProcessRunID wins over DEFENSECLAW_RUN_ID. Regressing this means
// fork/exec flows that rewrite the env (e.g. plugin subprocess)
// can desync run_id between the parent and child, breaking the join
// key on every audit row emitted after the drift.
func TestProcessRunID_AtomicOverridesEnv(t *testing.T) {
	t.Setenv("DEFENSECLAW_RUN_ID", "env-run-1")
	SetProcessRunID("atomic-run-1")
	t.Cleanup(func() { SetProcessRunID("") })

	if got := ProcessRunID(); got != "atomic-run-1" {
		t.Errorf("ProcessRunID()=%q, want atomic-run-1", got)
	}
}

// TestProcessRunID_FallsBackToEnv guards the legacy env path: when
// SetProcessRunID has not been called (early boot, test harnesses,
// pre-v7 consumers) we must still surface DEFENSECLAW_RUN_ID so the
// provenance quartet stays consistent with older tools that still
// read the env directly.
func TestProcessRunID_FallsBackToEnv(t *testing.T) {
	SetProcessRunID("")
	t.Cleanup(func() { SetProcessRunID("") })
	t.Setenv("DEFENSECLAW_RUN_ID", "env-run-2")

	if got := ProcessRunID(); got != "env-run-2" {
		t.Errorf("ProcessRunID()=%q, want env-run-2", got)
	}
}

// TestProcessRunID_EmptyWhenNeitherSet keeps the zero-value contract
// explicit: callers that observe ProcessRunID() == "" know to skip
// stamping rather than emit a literal "DEFENSECLAW_RUN_ID" or similar
// placeholder into SQLite.
func TestProcessRunID_EmptyWhenNeitherSet(t *testing.T) {
	SetProcessRunID("")
	t.Setenv("DEFENSECLAW_RUN_ID", "")

	if got := ProcessRunID(); got != "" {
		t.Errorf("ProcessRunID()=%q, want empty", got)
	}
}

// TestSetProcessRunID_TrimsWhitespace guards the invariant that
// newline/whitespace from env interpolation does not leak into SQLite
// — otherwise downstream joins on run_id get off-by-one every time
// the sidecar is launched via a shell wrapper that appends \n.
func TestSetProcessRunID_TrimsWhitespace(t *testing.T) {
	SetProcessRunID("  run-trim\n")
	t.Cleanup(func() { SetProcessRunID("") })

	if got := ProcessRunID(); got != "run-trim" {
		t.Errorf("ProcessRunID()=%q, want run-trim (whitespace trimmed)", got)
	}
}
