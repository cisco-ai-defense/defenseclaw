// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

// guardWatchEnded starts the reason of a trip on a guard watch that ended
// while the agent ran (GAP-0369).
const guardWatchEnded = "the guard's watch on the hook folder ended"

// guardDegraded is watchGuarded's error for a watch that cannot be set: the
// relay refuses the agent, logs relay.guard_degraded and reports it on the
// tamper route (GAP-0369).
type guardDegraded struct{ err error }

func (e *guardDegraded) Error() string {
	return "the guard cannot watch the hook folder: " + e.err.Error()
}

func (e *guardDegraded) Unwrap() error { return e.err }
