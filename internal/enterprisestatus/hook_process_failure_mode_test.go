// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0411: a managed Windows host listed four
// hook_process_fail_open warnings (claudecode, codex, copilot, hermes) next to
// hooks it renders fail-closed. Every one of them is real: each agent runs the
// tool when its hook process is killed or times out, whatever DefenseClaw's
// fail mode (support matrix, threat model). The warnings stay, and each now
// says that it is the agent's behavior, not the hook fail mode, and names the
// fail mode the connector's hooks are rendered with. Secure Client is
// unchanged.
func TestHookProcessFailureWarningNamesTheHookFailMode(t *testing.T) {
	for _, platform := range []string{"windows", "linux", "darwin"} {
		r := New("ensure", "standalone", platform, "1.0.7")
		r.SecurityComplete = true
		connectors := map[string]ConnectorState{}
		for _, name := range []string{"claudecode", "codex", "copilot", "hermes"} {
			connectors[name] = ConnectorState{Enabled: true, EffectiveHookFailMode: "closed"}
		}
		connectors["opencode"] = ConnectorState{Enabled: true, EffectiveHookFailMode: "closed"}
		r.AddHookProcessFailureWarnings(connectors)
		if len(r.Warnings) != 4 || r.SecurityComplete {
			t.Fatalf("%s: want the four real agent limits, got %d (security_complete %v): %v", platform, len(r.Warnings), r.SecurityComplete, r.Warnings)
		}
		for _, w := range r.Warnings {
			if w.Code != CodeHookProcessFailOpen ||
				!strings.Contains(w.Message, "This is the agent's own behavior, not DefenseClaw's fail mode: the managed hook still fails closed (effective_hook_fail_mode closed) when the gateway does not answer.") ||
				!strings.Contains(w.Message, "Protect the hook process from user signals with application control or EDR") {
				t.Fatalf("%s: warning does not explain the fail mode: %q", platform, w.Message)
			}
		}
	}
	open := New("status", "standalone", "linux", "1.0.7")
	open.AddHookProcessFailureWarnings(map[string]ConnectorState{"copilot": {Enabled: true, EffectiveHookFailMode: "open"}})
	if len(open.Warnings) != 1 || !strings.Contains(open.Warnings[0].Message, "The managed hook also fails open (effective_hook_fail_mode open)") ||
		strings.Contains(open.Warnings[0].Message, "still fails closed") {
		t.Fatalf("an open-mode hook must say it also fails open: %v", open.Warnings)
	}
	unknown := New("status", "standalone", "linux", "1.0.7")
	unknown.AddHookProcessFailureWarnings(map[string]ConnectorState{"codex": {Enabled: true}})
	if len(unknown.Warnings) != 1 || strings.Contains(unknown.Warnings[0].Message, "effective_hook_fail_mode") {
		t.Fatalf("without a known fail mode the warning names none: %v", unknown.Warnings)
	}
	sc := New("status", "secure_client", "windows", "1.0.7")
	sc.SecurityComplete = true
	sc.AddHookProcessFailureWarnings(map[string]ConnectorState{"codex": {Enabled: true, EffectiveHookFailMode: "closed"}})
	if len(sc.Warnings) != 0 || !sc.SecurityComplete {
		t.Fatalf("Secure Client changed: %v", sc.Warnings)
	}
}
