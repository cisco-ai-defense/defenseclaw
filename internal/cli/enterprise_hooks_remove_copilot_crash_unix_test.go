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
	"errors"
	"strings"
	"testing"
)

// GAP-1830: a worker that ends without an answer on a job for the VS Code
// Local files is reported under copilot, not as a claudecode removal.
func TestRemoveAllLabelsACrashedVSCodeLocalJobCopilot(t *testing.T) {
	unblock := enterpriseHookWorkerTarget{Index: 3, Mode: enterpriseHookWorkerModeUnblockPersonalClaude,
		Options: enterpriseHookWorkerOptions{ConnectorName: "claudecode", OwnerUID: 503, OwnerGID: 20}}
	carol := newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: 503, GID: 20, User: "carol", Home: "/home/carol"})
	carol.Request.CopilotVSCode = &enterpriseHookWorkerCopilotVSCode{HookBinary: "/opt/cisco/defenseclaw/bin/defenseclaw-hook", HookFile: true}
	unblock.Options.UserHome = "/home/carol"
	carol.Request.Targets = []enterpriseHookWorkerTarget{unblock}
	report := enterpriseHooksRemoveAllReport{}
	addEnterpriseHookRemoveRuns(&report, []enterpriseHookWorkerOutcome{{Job: *carol, Err: errors.New("worker crashed")}})
	if len(report.Failed) != 1 || !strings.HasPrefix(report.Failed[0], "carol/copilot: ") {
		t.Fatalf("a crashed VS Code Local job is reported as %v, want carol/copilot only", report.Failed)
	}
}
