// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0197: config validate prints the users-entry warnings the gateway
// reports to status and verify once it runs the file, so the bare name of a
// local account is named before the candidate is applied.
func TestConfigValidateNamesUnmatchedUsersEntries(t *testing.T) {
	good, goodDir := writeSandboxProfileConfig(t, "", "        required_for: [claudecode]\n")
	previous := configValidateUserEntryWarnings
	var asked int
	configValidateUserEntryWarnings = func(_ context.Context, assignments []config.ProfileAssignment) []string {
		asked++
		return []string{`assignment 1: users entry "e7local" names the local account e7local (uid 1601) of this host (profile_assignment_unmatched)`}
	}
	out := &strings.Builder{}
	configValidateCmd.SetOut(out)
	t.Cleanup(func() {
		configValidateUserEntryWarnings = previous
		configValidateCmd.SetOut(nil)
		configValidateJSON, configValidateDataDir = false, ""
	})
	configValidateDataDir = goodDir
	if err := configValidateCmd.RunE(configValidateCmd, []string{good}); err != nil {
		t.Fatalf("config validate refused a valid config: %v", err)
	}
	if asked != 1 || !strings.Contains(out.String(), "valid (config_version 9)") ||
		!strings.Contains(out.String(), `warning: assignment 1: users entry "e7local" names the local account`) {
		t.Fatalf("config validate output = %q (asked %d)", out.String(), asked)
	}
}
