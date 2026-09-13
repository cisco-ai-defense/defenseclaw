// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestStructuredSudoersWriteProjectsUnrestrictedGrant(t *testing.T) {
	facts := Analyze(Input{Tool: "write_file", Args: json.RawMessage(
		`{"path":"/etc/sudoers","content":"alice ALL=(ALL) NOPASSWD:ALL"}`,
	)})
	if !ExactPOSIXUnrestrictedSudoersGrantWrite(facts) ||
		!ExactPOSIXUnrestrictedSudoersGrantWrite(facts.EnforcementProjection()) {
		t.Fatalf("missing exact structured sudoers proof: %#v", facts)
	}
}

func TestStructuredSudoersWriteRejectsNearMisses(t *testing.T) {
	for _, args := range []string{
		`{"path":"/etc/sudoers","content":"alice ALL=(ALL) NOPASSWD:/usr/bin/id"}`,
		`{"path":"/etc/sudoers","content":"root ALL=(ALL) NOPASSWD:ALL"}`,
		`{"path":"/etc/sudoers.d/a/b","content":"alice ALL=(ALL) NOPASSWD:ALL"}`,
		`{"path":"/etc/sudoers","content":"$USER ALL=(ALL) NOPASSWD:ALL"}`,
		`{"path":"/etc/sudoers","content":"alice ALL=(ALL) NOPASSWD:ALL","note":"x"}`,
	} {
		facts := Analyze(Input{Tool: "write_file", Args: json.RawMessage(args)})
		if ExactPOSIXUnrestrictedSudoersGrantWrite(facts) {
			t.Fatalf("near miss produced proof: %s", args)
		}
	}
}
