// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterpriseunix

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// TestOpenCodeV1StatusLineNamesTheScanItReads (rel-1-0-10 GAP-0107): after
// V1 is replaced by V2 the OpenCode V1 warning stays until the enumerator's
// next cycle, because status reads its record and does not rescan. The
// warning names the scan time and says so, and no other warning gets the note.
func TestOpenCodeV1StatusLineNamesTheScanItReads(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	uid := 1001
	agents := []enterprisehooks.UnprotectedAgent{
		{User: "alice", UID: &uid, Connector: "opencode", Version: "1.18.34", InstallPath: "/home/alice/.npm-global/lib/node_modules/opencode-ai",
			Code: enterprisehooks.UnprotectedCodeHookContractUnverified, Reason: "version 1.18.34 is not verified against a known hook contract"},
		{User: "bob", UID: &uid, Connector: "codex", Version: "9.9.9", InstallPath: "/home/bob/codex",
			Code: enterprisehooks.UnprotectedCodeHookContractUnverified, Reason: "version 9.9.9 is not verified against a known hook contract"},
	}
	data, err := h.marshalCompletedScan(agents)
	if err != nil {
		t.Fatal(err)
	}
	record := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
	if err := os.WriteFile(record, data, 0o600); err != nil {
		t.Fatal(err)
	}
	scanAt := time.Now().Add(-3 * time.Minute).Truncate(time.Second)
	if err := os.Chtimes(record, scanAt, scanAt); err != nil {
		t.Fatal(err)
	}
	writeFreshLedger(t, h)

	result := h.run(Options{Action: ActionStatus})
	requireOK(t, result)
	var v1, other []string
	for _, m := range result.Warnings {
		switch m.Code {
		case enterprisehooks.UnprotectedCodeOpenCodeV1:
			v1 = append(v1, m.Message)
		case enterprisehooks.UnprotectedCodeHookContractUnverified:
			other = append(other, m.Message)
		}
	}
	if len(v1) != 1 {
		t.Fatalf("want one OpenCode V1 warning, got %d: %q", len(v1), v1)
	}
	for _, want := range []string{"scan that finished at " + scanAt.UTC().Format("2006-01-02 15:04:05") + " UTC", "status does not rescan", "next scan cycle"} {
		if !strings.Contains(v1[0], want) {
			t.Fatalf("the OpenCode V1 warning lacks %q: %q", want, v1[0])
		}
	}
	for _, m := range other {
		if strings.Contains(m, "status does not rescan") {
			t.Fatalf("a warning that is not OpenCode V1 carries the scan note: %q", m)
		}
	}
}
