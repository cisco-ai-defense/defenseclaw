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

// GAP-0929: the guardian records a configuration it could not check as a
// notice; the Windows status and verify read it apart from the agent
// settings notices, under its own warning code.
func TestTheGuardianRecordsANativeOTLPConfigItCouldNotCheck(t *testing.T) {
	dataDir := t.TempDir()
	writeEnterpriseHookGuardianNotices(io.Discard, dataDir, []enterpriseHookGuardianNotice{
		{User: "dcw-std1", Connector: "codex", AgentConfig: connector.AgentConfigNativeOTLPUnchecked},
		{User: "dcw-std2", Connector: "hermes", AgentConfig: connector.AgentConfigRecreatedHooksOnly},
	})
	otlp := enterpriseHookGuardianNativeOTLPMessages(dataDir)
	if len(otlp) != 1 || !strings.HasPrefix(otlp[0], "codex for user dcw-std1:") || !strings.Contains(otlp[0], "does not own") {
		t.Fatalf("native OTLP notices = %q", otlp)
	}
	settings := enterpriseHookGuardianNoticeMessages(dataDir)
	if len(settings) != 1 || !strings.HasPrefix(settings[0], "hermes for user dcw-std2:") {
		t.Fatalf("agent settings notices = %q", settings)
	}
}
