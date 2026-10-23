// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// hilt-preview loads config.yaml as the gateway does: a legacy
// claude_code.mode keeps Claude Code in action mode under an observe
// guardrail, and a profile that sets a mode replaces it.
func TestConnectorHILTPreviewUsesTheGatewayHookMode(t *testing.T) {
	home := t.TempDir()
	isolateHookEnvForTest(t, home)
	path := filepath.Join(home, "config.yaml")
	doc := "config_version: 9\nobservability: {}\nclaude_code:\n  mode: action\nguardrail:\n  mode: observe\n" +
		"  connectors:\n    claudecode:\n      mode: observe\n    codex: {}\n" +
		"  profiles:\n    audit:\n      mode: observe\n    plain:\n      block_at: HIGH\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := []any{connectorFlagName, hiltPreviewEnabled, hiltPreviewMinSeverity, hiltPreviewConfigPath}
	t.Cleanup(func() {
		connectorFlagName = previous[0].(string)
		hiltPreviewEnabled = previous[1].(bool)
		hiltPreviewMinSeverity = previous[2].(string)
		hiltPreviewConfigPath = previous[3].(string)
		connectorHILTPreviewCmd.SetOut(nil)
	})
	connectorFlagName, hiltPreviewEnabled, hiltPreviewMinSeverity, hiltPreviewConfigPath = "claude-code", true, "medium", path
	var out bytes.Buffer
	connectorHILTPreviewCmd.SetOut(&out)
	if err := runConnectorHILTPreview(connectorHILTPreviewCmd, nil); err != nil {
		t.Fatal(err)
	}
	var wire struct {
		WireVersion int    `json:"wire_version"`
		Connector   string `json:"connector"`
		Base        struct {
			Mode string `json:"mode"`
			HILT struct {
				Enabled     bool   `json:"enabled"`
				MinSeverity string `json:"min_severity"`
			} `json:"hilt"`
		} `json:"base"`
		Profiles []struct {
			Profile string `json:"profile"`
			Mode    string `json:"mode"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(out.Bytes(), &wire); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if wire.WireVersion != hiltPreviewWireVersion || wire.Connector != "claudecode" || wire.Base.Mode != "action" ||
		!wire.Base.HILT.Enabled || wire.Base.HILT.MinSeverity != "MEDIUM" {
		t.Fatalf("preview %s", out.String())
	}
	if len(wire.Profiles) != 2 || wire.Profiles[0].Profile != "audit" || wire.Profiles[0].Mode != "observe" ||
		wire.Profiles[1].Profile != "plain" || wire.Profiles[1].Mode != "action" {
		t.Fatalf("profiles %s", out.String())
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != doc {
		t.Fatalf("hilt-preview changed config.yaml: %v %q", err, after)
	}

	hiltPreviewMinSeverity = "SEVERE"
	if err := runConnectorHILTPreview(connectorHILTPreviewCmd, nil); err == nil {
		t.Fatal("an unknown severity was accepted")
	}
}
