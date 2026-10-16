// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-0588: the notice record is cross-platform, and the Windows status
// words it as Linux and macOS do: only known codes and connectors, with the
// account name kept plain.
func TestGuardianNoticeMessagesWordOnlyKnownNotices(t *testing.T) {
	// The Windows protected-file writer hands the record to the gateway
	// service account, which a test host does not have.
	enableEnterpriseHookGuardianRestores(t, true)
	dataDir := t.TempDir()
	writeEnterpriseHookGuardianNotices(io.Discard, dataDir, []enterpriseHookGuardianNotice{
		{User: "erin", Connector: "hermes", AgentConfig: connector.AgentConfigSettingsLost},
		{User: "bob\x1b[31m", Connector: "devin", AgentConfig: connector.AgentConfigRestoredLastGood},
		{User: "mallory", Connector: "hermes", AgentConfig: "\x1b[31m not a code"},
		{User: "alice", Connector: "codex", AgentConfig: connector.AgentConfigSettingsLost},
	})
	got := enterpriseHookGuardianNoticeMessages(dataDir)
	if len(got) != 2 ||
		!strings.HasPrefix(got[0], "devin for user bob[31m: the Devin config.json went missing; the guardian put back") ||
		!strings.HasPrefix(got[1], "hermes for user erin: the Hermes config.yaml went missing and DefenseClaw had no copy") {
		t.Fatalf("messages = %q", got)
	}
	if got := enterpriseHookGuardianNoticeMessages(t.TempDir()); got != nil {
		t.Fatalf("messages without a record = %q", got)
	}
}
