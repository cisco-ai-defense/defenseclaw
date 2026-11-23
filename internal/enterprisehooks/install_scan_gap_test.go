// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-10 GAP-0802: after a managed Windows upgrade the bounded scan of
// the homes of two enrolled accounts did not finish, and status and the
// Setup result called claudecode, codex, copilot and opencode of those
// accounts not protected (coverage_complete false), although the
// machine-wide managed hook fired for them. A gap in the private-install
// scan says nothing about the managed hook: with the hook verified for the
// account it is a warning that names the reason and the folder. A copy the
// scan found that the hook contract does not cover, a gap of an account whose
// hook is not verified, and every entry that is not a scan gap keep coverage
// incomplete.
func TestInstallScanGapWithAVerifiedManagedHookIsCovered(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	folder := filepath.Join(string(filepath.Separator)+"home", "alice", "work", "huge")
	gap, ok := privateInstallUnprotected(PrivateAgentInstall{Connector: "claudecode", Incomplete: true,
		Skipped: PrivateInstallSkippedHome, Folder: folder})
	if !ok || gap.Code != UnprotectedCodeInstallScanIncomplete || gap.Skipped != PrivateInstallSkippedHome || gap.Folder != folder {
		t.Fatalf("scan gap entry = %+v, want the skipped code and the folder", gap)
	}
	gap.User, gap.SID = "alice", sid
	verified := func(agent UnprotectedAgent) bool {
		return strings.EqualFold(agent.SID, sid) && agent.Connector == "claudecode"
	}

	// (1) The managed hook is verified: covered, and a warning that says so.
	if !InstallScanGapCovered(gap, verified) {
		t.Fatal("a scan gap of an account whose managed hook is verified leaves coverage incomplete")
	}
	partial := gap.InstallScanPartialMessage()
	for _, want := range []string{"claudecode for user alice (" + sid + ")", "managed hook", "verified",
		"could not be fully listed", folder, "application control"} {
		if !strings.Contains(partial, want) {
			t.Fatalf("partial scan warning %q does not contain %q", partial, want)
		}
	}
	if strings.Contains(partial, "not protected") {
		t.Fatalf("partial scan warning calls a verified account not protected: %q", partial)
	}

	// (3) No verified managed hook for the account: not covered, and the
	// NOT protected message names the folder too.
	for name, hookVerified := range map[string]func(UnprotectedAgent) bool{
		"nil":           nil,
		"unverified":    func(UnprotectedAgent) bool { return false },
		"other agent":   func(agent UnprotectedAgent) bool { return agent.Connector == "codex" },
		"other account": func(agent UnprotectedAgent) bool { return agent.SID == "S-1-5-21-1-2-3-1002" },
	} {
		if InstallScanGapCovered(gap, hookVerified) {
			t.Fatalf("%s: a scan gap without a verified managed hook counts as covered", name)
		}
	}
	if message := gap.Message(); !strings.Contains(message, "is not protected") || !strings.Contains(message, folder) {
		t.Fatalf("not-protected message = %q, want the folder", message)
	}

	// (2) A copy the scan found that the hook contract does not cover stays
	// not protected whatever the managed hook state.
	found, ok := privateInstallUnprotected(PrivateAgentInstall{Connector: "claudecode", Version: "1.0.0",
		Path: filepath.Join(string(filepath.Separator)+"home", "alice", "old", "node_modules", "@anthropic-ai", "claude-code"), Untrusted: true})
	if !ok {
		t.Fatal("an untrusted private copy is not reported")
	}
	found.User, found.SID = "alice", sid
	outside, _ := privateInstallUnprotected(PrivateAgentInstall{Connector: "claudecode", Incomplete: true, Skipped: PrivateInstallSkippedOutsideRoots})
	outside.User, outside.SID = "alice", sid
	legacy := UnprotectedAgent{User: "alice", SID: sid, Connector: "claudecode", Code: UnprotectedCodeInstallScanIncomplete,
		Reason: "the agent versions and private installs of the account could not be inspected this cycle"}
	for name, agent := range map[string]UnprotectedAgent{"found copy": found, "copy outside the scan roots": outside, "not a scan gap": legacy} {
		if InstallScanGapCovered(agent, verified) {
			t.Fatalf("%s counts as covered by the managed hook: %+v", name, agent)
		}
	}

	// The record keeps the code and the folder; an unknown code is dropped,
	// so a forged answer cannot select the covered verdict.
	forged := gap
	forged.User, forged.SID, forged.Skipped = "bob", "S-1-5-21-1-2-3-1003", "not_a_code"
	data, err := MarshalUnprotectedAgents([]UnprotectedAgent{gap, found, forged})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseUnprotectedAgents(data)
	if err != nil {
		t.Fatal(err)
	}
	covered := 0
	for _, agent := range parsed {
		if agent.User == "bob" && InstallScanGapCovered(agent, func(UnprotectedAgent) bool { return true }) {
			t.Fatalf("an unknown skipped code counts as a scan gap: %+v", agent)
		}
		if InstallScanGapCovered(agent, verified) {
			covered++
			if agent.Folder != folder || agent.Skipped != PrivateInstallSkippedHome {
				t.Fatalf("round trip lost the gap: %+v", agent)
			}
		}
	}
	if covered != 1 {
		raw, _ := json.Marshal(parsed)
		t.Fatalf("covered entries after the round trip = %d, want 1: %s", covered, raw)
	}
}
