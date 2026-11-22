// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package relay

// stopActorProcesses: actors are Linux; elsewhere only the agent's process
// group is stopped.
func stopActorProcesses(_ int, stopAgent func()) int {
	stopAgent()
	return 0
}
