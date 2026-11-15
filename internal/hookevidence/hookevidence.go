// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package hookevidence holds the query and the answer of a search of the
// gateway event history for the record a DefenseClaw hook left for a tool
// call. It has no dependencies, so the managed policy checks (enterprisepolicy)
// use it without linking the audit store into the hook binary.
package hookevidence

import "time"

// Query selects the v8 event-history record the gateway
// writes when a connector hook reports a tool call it is about to run
// (tool.invocation.requested).
type Query struct {
	// Connector is the connector the record must come from.
	Connector string
	// ToolCallID is the agent's tool call id (gen_ai.tool.call.id). It is an
	// identifier, which every built-in redaction profile keeps, unlike the
	// tool arguments.
	ToolCallID string
	// Since is the earliest record time accepted.
	Since time.Time
	// UserID, when set, is the OS user id the hook must have reported
	// (user.id).
	UserID string
}

// Evidence is what the event history holds for a query.
type Evidence struct {
	// Matched reports a record that meets every condition of the query.
	Matched bool
	// Mismatches describe records with the query's tool call id that fail
	// another condition.
	Mismatches []string
}
