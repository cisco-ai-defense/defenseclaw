// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "context"

// Inspector abstracts a Cisco AI Defense remote inspection client so the
// gateway can pick between the opensource API-key path
// (*CiscoInspectClient hitting /api/v1/inspect/chat) and the managed-mode
// CMID path (*CiscoDefenseClawInspectClient hitting
// /api/v1/inspect/defense_claw) without any downstream call site caring.
//
// Both implementations return the same *ScanVerdict shape so guardrail
// merging + audit trail behavior is identical.
//
// Nil-interface note: callers must nil-check the concrete constructor
// return value BEFORE assigning to an Inspector-typed variable. Assigning
// a typed-nil *CiscoInspectClient to an Inspector yields a non-nil
// interface whose Inspect() call NPEs. See guardrail_test.go for the
// canary that locks this behavior in.
type Inspector interface {
	Inspect(ctx context.Context, messages []ChatMessage) *ScanVerdict
	bindObservabilityV8(runtime hookLifecycleMetricV8Runtime)
}

// Compile-time assertion: the existing API-key client satisfies Inspector.
// The managed-mode client adds its own assertion in the same style.
var _ Inspector = (*CiscoInspectClient)(nil)
