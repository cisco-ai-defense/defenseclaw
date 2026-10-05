// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// The hook audit records the agent host tag so Devin Local under Devin
// Desktop is told apart from the Devin CLI.
func TestHookAuditRecordsTheAgentHost(t *testing.T) {
	header := http.Header{}
	header.Set(hookexec.AgentHostHeader, "Devin Helper (Plugin)")
	extra := hookRequestAuditExtra(withAgentHost(context.Background(), header), connector.HookProfile{})
	if got := extra[agentHostAuditExtra]; got != "devin-helper--plugin-" {
		t.Fatalf("agent_host = %q", got)
	}
	if _, present := hookRequestAuditExtra(withAgentHost(context.Background(), http.Header{}), connector.HookProfile{})[agentHostAuditExtra]; present {
		t.Fatal("no header, no agent_host")
	}
}
