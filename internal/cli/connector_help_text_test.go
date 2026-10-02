// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// GAP-1861: the connector help describes what the user can act on, not the
// internal resolution files, a misnamed config file or a legacy default.
func TestConnectorHelpHasNoInternalResolution(t *testing.T) {
	flag := connectorCmd.PersistentFlags().Lookup("connector")
	if flag == nil {
		t.Fatal("connector flag missing")
	}
	text := connectorCmd.Long + "\n" + flag.Usage
	for _, banned := range []string{"active_connector.json", "defenseclaw.yaml", "legacy default", "<data-dir>", "connector list"} {
		if strings.Contains(text, banned) {
			t.Errorf("connector help still contains %q:\n%s", banned, text)
		}
	}
	if !strings.Contains(text, "config.yaml") || !strings.Contains(text, "defenseclaw guardrail status") {
		t.Errorf("connector help should name config.yaml and defenseclaw guardrail status:\n%s", text)
	}
}
