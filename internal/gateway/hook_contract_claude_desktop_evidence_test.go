// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func stubClaudeDesktopEngine(t *testing.T, version string) *int {
	t.Helper()
	calls := 0
	prev := claudeDesktopEngineVersion
	claudeDesktopEngineVersion = func(context.Context, string) (string, string) {
		calls++
		if version == "" {
			return "", ""
		}
		return version, "/home/u/Library/Application Support/Claude-3p/claude-code"
	}
	t.Cleanup(func() { claudeDesktopEngineVersion = prev })
	return &calls
}

// GAP-0037: a Desktop-only per-user account (discovery found no claude CLI)
// is admitted in action mode against its Claude Desktop engine's contract,
// where it used to be refused as "discovery did not find the agent".
func TestClaudeDesktopEngineEvidenceAdmitsADesktopOnlyAccountInActionMode(t *testing.T) {
	cfg := evidenceTestConfig(t)
	s := &Sidecar{cfg: cfg}
	writeAgentDiscovery(t, cfg.DataDir, "claudecode", agentNotFound)
	stubClaudeDesktopEngine(t, "2.1.317")

	cached := connector.LoadCachedAgentVersion(cfg.DataDir, "claudecode")
	before := connector.ResolveHookContract("claudecode", cached)
	if before.Status != connector.HookCompatibilityUnversioned {
		t.Fatalf("without the engine the verdict is %q, want unversioned", before.Status)
	}
	if err := unversionedAgentAdmissionError(cfg.DataDir, "claudecode", cached, before.Reason); !errors.Is(err, ErrHookContractAdmission) {
		t.Fatalf("the old refusal = %v", err)
	}
	version, resolution := s.applyClaudeDesktopEngineEvidence("claudecode", cached, before)
	if version != "2.1.317" || resolution.Status != connector.HookCompatibilityKnown || resolution.Contract.ContractID != "claudecode-hooks-v2" {
		t.Fatalf("engine evidence = %q %q %q, want 2.1.317 known claudecode-hooks-v2", version, resolution.Status, resolution.Contract.ContractID)
	}
}

func TestClaudeDesktopEngineEvidenceKeepsEveryOtherVerdict(t *testing.T) {
	cfg := evidenceTestConfig(t)
	s := &Sidecar{cfg: cfg}
	calls := stubClaudeDesktopEngine(t, "2.1.317")

	// A version discovery recorded (the CLI, or the engine through GAP-0036) wins.
	cli := connector.ResolveHookContract("claudecode", "2.1.200 (Claude Code)")
	if v, r := s.applyClaudeDesktopEngineEvidence("claudecode", "2.1.200 (Claude Code)", cli); v != "2.1.200 (Claude Code)" || r.Status != cli.Status {
		t.Fatalf("cached version replaced: %q %q", v, r.Status)
	}
	// Another connector never reads Claude Desktop.
	unversioned := connector.ResolveHookContract("codex", "")
	if v, _ := s.applyClaudeDesktopEngineEvidence("codex", "", unversioned); v != "" {
		t.Fatalf("codex got %q", v)
	}
	if *calls != 0 {
		t.Fatalf("engine read %d times for a versioned or other connector", *calls)
	}
	// Managed installs keep their own (machine policy) admission.
	cfg.DeploymentMode = "managed_enterprise"
	if v, _ := s.applyClaudeDesktopEngineEvidence("claudecode", "", connector.ResolveHookContract("claudecode", "")); v != "" || *calls != 0 {
		t.Fatalf("managed install used the engine: %q (%d reads)", v, *calls)
	}
	// No verified engine: the unversioned verdict stays (action mode refuses).
	cfg.DeploymentMode = ""
	stubClaudeDesktopEngine(t, "")
	before := connector.ResolveHookContract("claudecode", "")
	if v, r := s.applyClaudeDesktopEngineEvidence("claudecode", "", before); v != "" || r.Status != before.Status {
		t.Fatalf("no engine: %q %q", v, r.Status)
	}
}
