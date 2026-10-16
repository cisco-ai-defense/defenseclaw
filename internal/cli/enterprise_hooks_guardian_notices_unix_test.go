// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-0564: the guardian records which protected targets had their agent
// config put back or recreated, in a file of its own (the guardian state
// keeps the schema a prior binary reads strictly), with only the known codes
// the per-user worker may report.
func TestGuardianRecordsAgentConfigNoticesInTheirOwnFile(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, hookGuardianNoticesFile)
	writeEnterpriseHookGuardianNotices(io.Discard, dataDir, []enterpriseHookGuardianNotice{
		{User: "erin", Connector: "hermes", AgentConfig: connector.AgentConfigSettingsLost},
		{User: "bob", Connector: "devin", AgentConfig: "\x1b[31m not a code"},
	})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record enterpriseHookGuardianNoticeRecord
	if err := json.Unmarshal(data, &record); err != nil || record.Version != 1 || len(record.Targets) != 1 ||
		record.Targets[0].User != "erin" || record.Targets[0].AgentConfig != connector.AgentConfigSettingsLost {
		t.Fatalf("record = %s (%v)", data, err)
	}
	// An unchanged set is not rewritten; a pass without notices removes it.
	writeEnterpriseHookGuardianNotices(io.Discard, dataDir, []enterpriseHookGuardianNotice{{User: "erin", Connector: "hermes", AgentConfig: connector.AgentConfigSettingsLost}})
	if again, _ := os.ReadFile(path); string(again) != string(data) {
		t.Fatalf("an unchanged set was rewritten:\n%s\n%s", data, again)
	}
	writeEnterpriseHookGuardianNotices(io.Discard, dataDir, nil)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the record stayed after a pass without notices: %v", err)
	}
}

// The worker runs as the account: an answer naming an agent config status
// the installer does not return is refused, like any other inconsistent one.
func TestWorkerResultWithAnUnknownAgentConfigStatusIsRefused(t *testing.T) {
	home := t.TempDir()
	target := enterpriseHookWorkerTarget{Options: enterpriseHookWorkerOptions{ConnectorName: "hermes", UserHome: home}}
	answer := enterpriseHookWorkerTargetResult{OK: true, Result: &enterprisehooks.InstallResult{Connector: "hermes", UserHome: home}, AgentConfig: connector.AgentConfigRestoredLastGood}
	if err := validateEnterpriseHookWorkerResult(target, answer); err != nil {
		t.Fatalf("a known status was refused: %v", err)
	}
	answer.AgentConfig = "anything else"
	if err := validateEnterpriseHookWorkerResult(target, answer); err == nil || !strings.Contains(err.Error(), "agent config status") {
		t.Fatalf("an unknown status = %v", err)
	}
}
