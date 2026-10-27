// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"slices"
	"testing"
)

// GAP-1828: the uninstall names each account whose Claude Code blocker it
// removed, so its owner knows its own Claude Code hook needs
// `defenseclaw setup claude-code` again.
func TestRemoveAllReportsUnblockedClaudeHooks(t *testing.T) {
	unblock := enterpriseHookWorkerTarget{Index: 3, Mode: enterpriseHookWorkerModeUnblockPersonalClaude,
		Options: enterpriseHookWorkerOptions{ConnectorName: "claudecode", UserHome: "/home/bob", OwnerUID: 502, OwnerGID: 20}}
	bob := newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: 502, GID: 20, User: "bob", Home: "/home/bob"})
	bob.Request.Targets = []enterpriseHookWorkerTarget{unblock}
	report := enterpriseHooksRemoveAllReport{}
	addEnterpriseHookRemoveRuns(&report, []enterpriseHookWorkerOutcome{{Job: *bob, Response: enterpriseHookWorkerResponse{
		Targets: []enterpriseHookWorkerTargetResult{{Index: 3, OK: true, Removed: true}},
	}}})
	if !slices.Equal(report.ClaudeHookUnblocked, []string{"bob"}) || report.Removed != 1 || len(report.Failed) != 0 {
		t.Fatalf("report %+v", report)
	}
}
