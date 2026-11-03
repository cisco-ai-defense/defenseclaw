// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestWindowsStatusNamesADisabledCodex is rel-1-0-6:GAP-0325 on Windows:
// with guardrail.connectors.codex.enabled false the Windows lifecycle
// removes the Codex machine requirements and the hook is a no-op without
// them; status now lists Codex with enabled false (a contract-valid entry
// with targets) and the text summary names it disabled.
func TestWindowsStatusNamesADisabledCodex(t *testing.T) {
	off := false
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {Enabled: &off}, "claudecode": {}}
	fakeWindowsStatusV2(t, windowsEnterpriseStatusV2Inputs{
		cfg:           cfg,
		manifest:      []enterprisestatus.ConnectorInstall{{Connector: "claudecode", Version: "2.1.314", Enabled: true}},
		guardianKnown: true,
		guardian:      []enterprisestatus.ConnectorTarget{{Connector: "claudecode", OK: true}},
	})
	result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.7")
	result.Installed, result.InstalledVersion = true, "1.0.7"
	applyWindowsEnterpriseStatusV2(result)
	result.Finish("windows", 0)
	document, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	contracttest.Compile(t).Validate(t, "lifecycle-result.schema.json", document)
	codex, ok := result.Connectors["codex"]
	if !ok || codex.Enabled || codex.Targets == nil || codex.Targets.Total != 0 || codex.HooksInstalled != enterprisestatus.HooksInstalledNone {
		t.Fatalf("codex = %+v (ok=%v), want enabled false, no targets, hooks none", codex, ok)
	}
	var text bytes.Buffer
	writeWindowsEnterpriseStandaloneSummary(&text, result)
	if !strings.Contains(text.String(), "connectors: claudecode enabled, codex disabled") {
		t.Fatalf("summary does not name the disabled connector:\n%s", text.String())
	}
}
