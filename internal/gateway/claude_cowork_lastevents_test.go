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
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/coworkaudit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// A Cowork hook call the gateway records is the account's last Cowork event
// the enterprise status lookup reads from the audit store; a terminal Claude
// Code call is not.
func TestCoworkHookRowIsTheStatusLastEvent(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	engine, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: engine})
	store, path := fixture.store, fixture.path
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	payload := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "c29dbbfa-8209-4e91-84c4-7191c9491c94",
		"tool_name": "mcp__workspace__bash", "tool_input": map[string]interface{}{"command": "echo ok"},
		"mcp_server": map[string]interface{}{"name": "workspace", "source": "sdk"},
	}
	before := time.Now().Add(-time.Minute)
	// A terminal call first: it must not count as Cowork.
	postCoworkCapture(t, api, map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "terminal-1", "tool_name": "Bash",
		"tool_input": map[string]interface{}{"command": "echo ok"},
	}, nil)
	if events, _, err := coworkaudit.LastEvents(context.Background(), path); err != nil || len(events) != 0 {
		t.Fatalf("after a terminal call: events=%v err=%v, want none", events, err)
	}
	postCoworkCapture(t, api, payload, &hookexec.CoworkContext{SessionID: "c29dbbfa-8209-4e91-84c4-7191c9491c94"})
	events, truncated, err := coworkaudit.LastEvents(context.Background(), path)
	if err != nil || truncated || len(events) != 1 {
		t.Fatalf("LastEvents = %v, %v, %v; want one account", events, truncated, err)
	}
	if events[0].At.Before(before) || events[0].At.After(time.Now().Add(time.Minute)) {
		t.Fatalf("last Cowork event at %s, want now", events[0].At)
	}
}
