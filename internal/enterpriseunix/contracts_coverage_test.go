// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0151: an enrolled managed Hermes whose version has no verified hook
// contract has no DefenseClaw hook, so status and verify report the
// deployment as not covering it (coverage_complete false) and name the agent
// with hook_contract_unverified. A target the guardian failed for another
// reason keeps its own warning and leaves coverage as it was.
func TestAgentWithoutAHookContractIsNotCovered(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	writeState := func(results ...map[string]any) {
		t.Helper()
		if results == nil {
			results = []map[string]any{}
		}
		state, _ := json.Marshal(map[string]any{"results": results})
		if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
			t.Fatal(err)
		}
	}

	writeState(map[string]any{"user": "carol", "connector": "codex", "ok": false,
		"error": "enterprise hooks: connector codex setup failed: executable is not in a trusted install prefix"})
	if baseline := h.run(Options{Action: ActionStatus}); !baseline.CoverageComplete {
		t.Fatalf("baseline status is not coverage complete: readiness=%+v", baseline.Readiness)
	}

	writeState(
		map[string]any{"user": "dcr-std1", "connector": "hermes", "ok": true},
		map[string]any{"user": "r103t8h", "connector": "hermes", "ok": false,
			"error": `enterprise hooks: connector hermes agent version "0.18.0" is not verified against a known hook contract: no hook contract matches normalized agent version`},
	)
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if r.CoverageComplete || r.SecurityComplete {
			t.Fatalf("%s: coverage_complete=%t security_complete=%t with an agent that has no hook", action, r.CoverageComplete, r.SecurityComplete)
		}
		if msg := messagesOf(r.Warnings, codeHookContractUnverified); !strings.Contains(msg, "hermes 0.18.0 for user r103t8h") ||
			!strings.Contains(msg, "runs without DefenseClaw hooks") {
			t.Fatalf("%s: hook_contract_unverified warning = %q", action, msg)
		}
	}

	// The enumerator's unprotected-agents record says the same for an agent
	// it could not enroll because its version has no hook contract.
	writeState()
	// The entries are the ones EnumerateUnix writes for a Hermes 0.18.0 and
	// for a Hermes whose version it cannot read
	// (TestEnumerateUnixEnrollsNoHermesWithoutAHookContract).
	data, err := enterprisehooks.MarshalUnprotectedAgents([]enterprisehooks.UnprotectedAgent{{
		User:      "r103t8h",
		Connector: "hermes",
		Version:   "0.18.0",
		Code:      enterprisehooks.UnprotectedCodeHookContractUnverified,
		Reason:    "version 0.18.0 is not verified against a known hook contract (no hook contract matches normalized agent version); DefenseClaw installs no hooks for it, so it runs without DefenseClaw hooks",
	}, {
		User:      "r103t8i",
		Connector: "hermes",
		Code:      enterprisehooks.UnprotectedCodeHookContractUnverified,
		Reason:    "installed, but its version could not be read: /home/r103t8i/.local/bin/hermes; DefenseClaw cannot select a hook contract without a version, so it runs without DefenseClaw hooks",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		// A warning: verify still succeeds (exit code 0).
		requireOK(t, r)
		msg := messagesOf(r.Warnings, enterprisehooks.UnprotectedCodeHookContractUnverified)
		if r.CoverageComplete || r.SecurityComplete ||
			!strings.Contains(msg, "hermes 0.18.0 for user r103t8h is not protected") ||
			!strings.Contains(msg, "hermes for user r103t8i is not protected: installed, but its version could not be read") ||
			strings.Count(msg, "runs without DefenseClaw hooks") != 2 {
			t.Fatalf("%s with the unprotected-agents record: coverage_complete=%t security_complete=%t warnings=%q",
				action, r.CoverageComplete, r.SecurityComplete, msg)
		}
	}
}
