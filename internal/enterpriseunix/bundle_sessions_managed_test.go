// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A session of an agent the installed config does not enable runs no
// DefenseClaw hook before or after any bundle, so no restart can bring it
// under enforcement: sessions_restart_required counts only the connectors
// the installed config enables (management-agent.md 4.3, "a session that was
// already running when a bundle enabled or changed its connector"). On a
// Codex-only device the old Claude Code sessions kept the device from ever
// reporting fully enforcing (sidecar F04).
func TestBundleSessionsCountOnlyEnabledConnectors(t *testing.T) {
	h := newTestHost(t, "darwin")
	codexOnly := strings.Replace(string(readSampleConfig(t, "macos-standalone.yaml")), "    claudecode: {}\n", "", 1)
	if codexOnly == string(readSampleConfig(t, "macos-standalone.yaml")) {
		t.Fatal("the sample config no longer enables claudecode; update this test")
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(codexOnly))}))
	applied := time.Now().UTC().Add(-time.Hour)
	state, _ := json.Marshal(enterprisestatus.PolicyStateRecord{AppliedAt: applied.Format(time.RFC3339Nano)})
	writeHostFile(t, h, filepath.Join(h.env.Layout.LifecycleDir, enterprisestatus.PolicyStateFileName), string(state))
	ps := ""
	for pid := 501; pid <= 508; pid++ {
		ps += strings.Join([]string{strconv.Itoa(pid), "502", "2-00:00:00", "/usr/local/bin/claude"}, " ") + "\n"
	}
	ps += strings.Join([]string{"601", "502", "2-00:00:00", "/opt/homebrew/bin/codex"}, " ") + "\n"
	h.runner.replies = map[string]fakeReply{"ps -axww -o pid=,uid=,etime=,args=": {result: CommandResult{Stdout: []byte(ps)}}}

	status := h.env.UnprotectedSessions(context.Background())
	if status.State != "known" || status.Count != 1 || len(status.Entries) != 1 || status.Entries[0].Agent != "codex" {
		t.Fatalf("sessions on a Codex-only device = %+v, want only the old Codex session", status)
	}
}
