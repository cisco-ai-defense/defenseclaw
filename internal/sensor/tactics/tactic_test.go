// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tactics

import (
	"reflect"
	"testing"
)

func TestChainStageOrdersTheKillChain(t *testing.T) {
	t.Parallel()
	// The order is load-bearing, not cosmetic: AgentSession scoring awards the
	// chain bonus only for stages observed in increasing order, so reordering
	// these silently changes what counts as an incident.
	want := []Tactic{
		LocalInference, CredentialAccess, IdentityCreation,
		PrivilegeEscalation, Persistence, Exfiltration,
	}
	for index, tactic := range want {
		if got := ChainStage(tactic); got != index {
			t.Errorf("ChainStage(%s) = %d, want %d", tactic, got, index)
		}
	}
	if got := ChainStage("not_a_tactic"); got != -1 {
		t.Errorf("ChainStage of an unknown tactic = %d, want -1", got)
	}
}

func TestEveryTacticCarriesAnAttackTechnique(t *testing.T) {
	t.Parallel()
	// Every emitted record carries the technique so a SOC can pivot on a
	// vocabulary it already uses. A tactic without one silently degrades that.
	for _, tactic := range ChainOrder {
		if tactic.Technique() == "" {
			t.Errorf("tactic %s has no ATT&CK technique", tactic)
		}
		if !tactic.Valid() {
			t.Errorf("tactic %s in ChainOrder is not Valid()", tactic)
		}
	}
}

func TestForSignalsReturnsDistinctTacticsInChainOrder(t *testing.T) {
	t.Parallel()
	// Deliberately supplied out of order and with a duplicate: two persistence
	// signals are one stage, not two, or a single agent rewriting two config
	// files would look like progression.
	got := ForSignals([]string{
		"agent_public_exfil_surface",
		"agent_persistence",
		"agent_credential_access",
		"agent_config_persistence",
		"not_a_signal",
	})
	want := []Tactic{CredentialAccess, Persistence, Exfiltration}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ForSignals() = %v, want %v", got, want)
	}
}

func TestForSignalsIgnoresUnknownSignalsRatherThanGuessing(t *testing.T) {
	t.Parallel()
	if got := ForSignals([]string{"shadow_ai_egress", "inference_heartbeat"}); len(got) != 0 {
		t.Fatalf("ForSignals() = %v, want empty: plane A/B signals are not host-plane tactics", got)
	}
}

func TestIsAgentProcessMatchesKnownAgentsOnly(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"claude", "Claude", "codex", "cursor-agent", "aider", "devin",
		"/usr/local/bin/claude",
		// Windows ships every one of these as an executable. A pattern that
		// did not tolerate the extension would gate the entire host plane on
		// that platform, which a real Windows host demonstrated.
		`C:\Program Files\Amp\amp.exe`, "claude.exe", "CODEX.EXE", "cursor-agent.cmd",
	} {
		if !IsAgentProcess(name) {
			t.Errorf("IsAgentProcess(%q) = false, want true", name)
		}
	}
	for _, name := range []string{
		"python3", "node", "bash", "sh", "", "   ", "claudette", "not-claude",
		// An extension is tolerated, not a suffix: claude-helper is not claude.
		"claude-helper.exe", "codexify.exe", "claude.exe.bak",
	} {
		if IsAgentProcess(name) {
			t.Errorf("IsAgentProcess(%q) = true, want false", name)
		}
	}
}

func TestAgentCmdlineReasonClosesTheGenericInterpreterGap(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ cmdline, want string }{
		{"python3 -m langgraph.cli run", "agent framework module"},
		// mcpProcessPattern is checked before the pattern list, and
		// "@modelcontextprotocol/" contains "modelcontextprotocol", so this
		// classifies as a process rather than a package. Both answers put the
		// observation on the same tactic, so the precedence is harmless -- it
		// is pinned here so a later reorder is a deliberate choice.
		{"node /opt/x/@modelcontextprotocol/server-filesystem", "MCP server process"},
		{"python3 -m mcp_server_git", "MCP server process"},
		{"npx mcp-server-fetch", "MCP server process"},
		{"python3 -c 'import crewai'", "agent framework module"},
		{"ollama run llama3", "provider SDK CLI"},
	} {
		if got := AgentCmdlineReason(test.cmdline); got != test.want {
			t.Errorf("AgentCmdlineReason(%q) = %q, want %q", test.cmdline, got, test.want)
		}
	}
	for _, cmdline := range []string{"", "   ", "python3 manage.py runserver", "grep -r ollama ."} {
		if got := AgentCmdlineReason(cmdline); got != "" {
			t.Errorf("AgentCmdlineReason(%q) = %q, want no match", cmdline, got)
		}
	}
}

func TestAgentIdentityPrefersTheNameOverTheCommandLine(t *testing.T) {
	t.Parallel()
	// A name we recognise beats a command line we merely find suggestive.
	if got := AgentIdentity("/usr/bin/claude", "python3 -m langgraph"); got != "claude" {
		t.Errorf("AgentIdentity() = %q, want %q", got, "claude")
	}
	if got := AgentIdentity("python3", "python3 -m crewai"); got != "python3" {
		t.Errorf("AgentIdentity() = %q, want %q", got, "python3")
	}
	// An empty executable with a suggestive command line still names something,
	// because the lineage gate needs a responsible actor to attribute to.
	if got := AgentIdentity("", "npx @modelcontextprotocol/server-git"); got != "agent" {
		t.Errorf("AgentIdentity() = %q, want %q", got, "agent")
	}
	if got := AgentIdentity("python3", "python3 manage.py runserver"); got != "" {
		t.Errorf("AgentIdentity() = %q, want no identity", got)
	}
}

func TestBaseNameHandlesBothSeparators(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ in, want string }{
		{"/usr/local/bin/claude", "claude"},
		{`C:\Users\dev\AppData\codex.exe`, "codex.exe"},
		{"claude", "claude"},
		{"  /opt/claude  ", "claude"},
		{"", ""},
	} {
		if got := BaseName(test.in); got != test.want {
			t.Errorf("BaseName(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}
