// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package connector

// accountAgentProcessMayRun cannot list the account's processes here, so a
// process that may run the agent is assumed and its hook tombstone stays.
func accountAgentProcessMayRun(string, string) bool { return true }
