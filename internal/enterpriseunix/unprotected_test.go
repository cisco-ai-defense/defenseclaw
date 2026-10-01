// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// An agent the enumerator found installed for a user but could not enroll
// runs without DefenseClaw hooks. Status and verify name it as a warning for
// that account and report the deployment security-incomplete; verify does
// not fail the host for it.
func TestUnprotectedAgentsAreVisible(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	data, err := enterprisehooks.MarshalUnprotectedAgents([]enterprisehooks.UnprotectedAgent{{
		User:      "alice",
		Connector: "opencode",
		Code:      enterprisehooks.UnprotectedCodeAgentUnprotected,
		Reason:    "installed, but its version could not be read: /home/alice/.local/bin/opencode; it runs without DefenseClaw hooks",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
		t.Fatal(err)
	}
	status := h.run(Options{Action: ActionStatus})
	requireOK(t, status)
	if status.SecurityComplete {
		t.Fatal("status reports security_complete with an unprotected agent")
	}
	found := false
	for _, w := range status.Warnings {
		if w.Code == codeAgentUnprotected && strings.Contains(w.Message, "opencode for user alice is not protected: installed, but its version could not be read") {
			found = true
		}
	}
	if !found {
		t.Fatalf("status warnings do not name the unprotected agent: %+v", status.Warnings)
	}
	writeFreshLedger(t, h)
	verify := h.run(Options{Action: ActionVerify})
	requireOK(t, verify)
	if verify.SecurityComplete || messagesOf(verify.Warnings, codeAgentUnprotected) == "" {
		t.Fatalf("verify does not keep the unprotected agent as a warning: %+v", verify)
	}

	// An empty record (every agent enrolled again) clears the finding.
	empty, _ := enterprisehooks.MarshalUnprotectedAgents(nil)
	if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), empty, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, w := range h.run(Options{Action: ActionStatus}).Warnings {
		if w.Code == codeAgentUnprotected {
			t.Fatalf("an empty record still reports: %+v", w)
		}
	}
}
