// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Every unprotected-agents entry that is OpenCode V1 (rel-1-0-6 GAP-0037)
// reads back with its own code and the remedy, whichever enumerator path
// wrote it and on whichever OS; other entries keep theirs.
func TestOpenCodeV1EntriesGetTheirCodeAndRemedy(t *testing.T) {
	uid := 1001
	agents := []UnprotectedAgent{
		// Linux and macOS separate-copy scan: the V1 package in a machine prefix.
		{User: "alice", UID: &uid, Connector: "opencode", Version: "1.18.34", InstallPath: "/opt/dc-agents/lib/node_modules/opencode-ai",
			Code: UnprotectedCodeHookContractUnverified, Reason: "version 1.18.34 is not verified against a known hook contract"},
		// The selected version of the machine-policy connector, no path.
		{User: "bob", Connector: "opencode", Version: "1.18.34", Code: UnprotectedCodeHookContractUnverified, Reason: "version 1.18.34 is not verified"},
		// A copy another account can change: no trusted version, the V1 folder.
		{User: "carol", Connector: "opencode", InstallPath: "/opt/shared/lib/node_modules/opencode-ai",
			Code: UnprotectedCodeHookContractUnverified, Reason: privateInstallUntrustedReason},
		// Windows separate-copy scan.
		{User: "dave", SID: "S-1-5-21-1-2-3-1004", Connector: "opencode", Version: "1.18.34",
			InstallPath: `C:\Users\dave\AppData\Roaming\npm\node_modules\opencode-ai`, Code: UnprotectedCodeHookContractUnverified, Reason: "below"},
		// Not OpenCode V1: OpenCode V2 newer than the contract, an incomplete
		// scan, another connector at 1.x.
		{User: "erin", Connector: "opencode", Version: "3.0.0", Code: UnprotectedCodeHookContractUnverified, Reason: "OpenCode V2 is required"},
		{User: "erin", Connector: "opencode", Code: UnprotectedCodeInstallScanIncomplete, Reason: "the bounded scan was incomplete"},
		{User: "erin", Connector: "codex", Version: "1.0.0", Code: UnprotectedCodeHookContractUnverified, Reason: "version 1.0.0 is not verified"},
	}
	data, err := MarshalUnprotectedAgents(agents)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseUnprotectedAgents(data)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]string{}
	for _, agent := range parsed {
		key := agent.User + " " + agent.Connector + " " + agent.Code
		codes[key] = agent.Message()
		if agent.Code == UnprotectedCodeOpenCodeV1 && agent.Reason != openCodeV1Reason {
			t.Fatalf("V1 reason was cut or changed: %q", agent.Reason)
		}
	}
	for _, user := range []string{"alice", "bob", "carol", "dave"} {
		message, ok := codes[user+" opencode "+UnprotectedCodeOpenCodeV1]
		if !ok {
			t.Fatalf("%s: OpenCode V1 entry not classified: %v", user, codes)
		}
		for _, want := range []string{"is not protected: it is OpenCode V1 (opencode-ai)", "OpenCode is NOT protected until OpenCode V2 (@opencode/cli 2.x) is installed",
			"npm uninstall -g opencode-ai", "npm install -g @opencode/cli@2", "opencode service restart"} {
			if !strings.Contains(message, want) {
				t.Fatalf("%s: message %q lacks %q", user, message, want)
			}
		}
	}
	if !strings.HasPrefix(codes["alice opencode "+UnprotectedCodeOpenCodeV1], "opencode 1.18.34 at /opt/dc-agents/lib/node_modules/opencode-ai for user alice") {
		t.Fatalf("message does not name the copy: %q", codes["alice opencode "+UnprotectedCodeOpenCodeV1])
	}
	for _, key := range []string{"erin opencode " + UnprotectedCodeHookContractUnverified, "erin opencode " + UnprotectedCodeInstallScanIncomplete,
		"erin codex " + UnprotectedCodeHookContractUnverified} {
		if _, ok := codes[key]; !ok {
			t.Fatalf("%q was reclassified: %v", key, codes)
		}
	}
	if n := utf8.RuneCountInString(openCodeV1Reason); n > unprotectedReasonMaxRunes {
		t.Fatalf("the V1 reason has %d runes, more than the record keeps (%d)", n, unprotectedReasonMaxRunes)
	}
}

// OpenCode V1 makes coverage_complete false on Linux, macOS and Windows,
// as an agent without a hook contract does; an agent the enumerator could
// only not enroll leaves coverage alone.
func TestUnprotectedCodeLeavesCoverageIncomplete(t *testing.T) {
	for code, want := range map[string]bool{
		UnprotectedCodeOpenCodeV1:                   true,
		UnprotectedCodeHookContractUnverified:       true,
		UnprotectedCodeInstallScanIncomplete:        true,
		UnprotectedCodeKiroCLIBelowHookFloor:        true,
		UnprotectedCodeKiroIDEBelowGlobalHooksFloor: true,
		UnprotectedCodeAgentUnprotected:             false,
		UnprotectedCodeSurfaceUnverified:            false,
		UnprotectedCodeHomeUntrusted:                false,
	} {
		if got := UnprotectedCodeLeavesCoverageIncomplete(code); got != want {
			t.Fatalf("%s: coverage incomplete = %v, want %v", code, got, want)
		}
	}
}
