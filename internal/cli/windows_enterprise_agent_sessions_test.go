// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// GAP-0755: an agent CLI a user opened before the Windows deployment was
// installed (natively or through node) is named per account with
// agent_sessions_restart_required; later sessions, service accounts and
// other programs are not.
func TestWindowsAgentSessionWarningsNameSessionsStartedBeforeTheInstall(t *testing.T) {
	installed := time.Date(2026, 10, 8, 11, 40, 0, 0, time.UTC)
	before, after := installed.Add(-time.Minute), installed.Add(time.Minute)
	rows := []procprobe.Process{
		{PID: 11, Name: "claude.exe", User: "dcw-ew3a1", StartedAt: before},
		{PID: 12, Name: "node.exe", Cmdline: `"C:\Program Files\nodejs\node.exe" C:\Users\u2\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js`, User: "dcw-ew3a2", StartedAt: before},
		{PID: 13, Name: "claude.exe", User: "dcw-ew3a1", StartedAt: after},
		{PID: 14, Name: "codex.exe", User: "SYSTEM", StartedAt: before},
		{PID: 15, Name: "notepad.exe", User: "dcw-ew3a1", StartedAt: before},
		{PID: 16, Name: "node.exe", Cmdline: "node server.js", User: "dcw-ew3a2", StartedAt: before},
	}
	warnings := windowsAgentSessionWarnings(windowsAgentSessionsBefore(rows, installed), installed)
	if len(warnings) != 2 || warnings[0].Code != "agent_sessions_restart_required" ||
		!strings.Contains(warnings[0].Message, "user dcw-ew3a1 runs claude (pid 11), started before") ||
		!strings.Contains(warnings[1].Message, "user dcw-ew3a2 runs claude (pid 12)") {
		t.Fatalf("warnings = %+v", warnings)
	}
}
