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
	"os"
	"strings"
	"sync/atomic"
)

// runID is the per-process run identifier stamped on every event
// whose caller did not set one. It is functionally parallel to
// sidecarInstanceID but semantically distinct: sidecar_instance_id
// rotates on every sidecar process, while run_id rotates on every
// "gateway run" — which in v7 is still 1:1 with the sidecar process,
// but the separation is intentional so operators can pivot either way
// in dashboards.
//
// Source of truth precedence:
//
//  1. Explicit caller value on gatewaylog.Event / audit.Event (never
//     overwritten).
//  2. Atomic process-wide value set at boot via SetProcessRunID
//     (preferred, survives env-var drift across fork/exec).
//  3. DEFENSECLAW_RUN_ID env var (legacy — kept so pre-v7 callers that
//     only read the env still see a consistent id).
//
// The setter is usually called exactly once during sidecar boot: the
// caller reads DEFENSECLAW_RUN_ID, mints a UUID if empty, and installs
// the result here plus mirrors it back into the env (so child
// processes and legacy env readers still pick it up). Tests can clear
// the atomic by calling SetProcessRunID("").
var runID atomic.Value

// SetProcessRunID installs the per-process run UUID. Trims whitespace
// so the reader does not have to worry about stray newlines from env
// interpolation.
func SetProcessRunID(id string) {
	runID.Store(strings.TrimSpace(id))
}

// ProcessRunID returns the currently installed run id, preferring the
// atomic slot set at boot over the legacy env var. Returns "" when
// neither is set (unit tests that never seed it, or boot paths that
// run before SetProcessRunID).
func ProcessRunID() string {
	if v, _ := runID.Load().(string); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("DEFENSECLAW_RUN_ID"))
}
