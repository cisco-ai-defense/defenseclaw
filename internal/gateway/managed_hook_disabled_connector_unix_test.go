// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// disabledConnectorSocketAPI is a standalone managed gateway in action mode
// whose guardrail.connectors names Claude Code and Codex, Codex with
// enabled set as given, behind the hook socket's peer authorization with an
// empty guardian ledger: no account is enrolled for any connector.
func disabledConnectorSocketAPI(t *testing.T, codexEnabled bool, enrollment config.EnterpriseEnrollmentConfig) http.Handler {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {},
		"codex":      {Enabled: &codexEnabled},
	}
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger, connectorRegistry: connector.NewDefaultRegistry()}
	empty := func() (managedHookLedger, error) { return managedHookLedger{}, nil }
	// Neither connector is in machine policy: the lifecycle removed Codex's
	// requirements, and Claude Code is held to per-user enrollment here so
	// the empty ledger refuses it.
	return api.managedHookPeerAuth(newManagedHookAuthorizer(enrollment, nil, empty), api.managedHookSocketMux())
}

func postDisabledConnectorHook(t *testing.T, handler http.Handler, path, body string, headers map[string]string, peer managedHookPeer) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "hook")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req = req.WithContext(withManagedHookPeer(req.Context(), peer))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

const disabledCodexPreToolUse = `{"hook_event_name":"PreToolUse","session_id":"s1","turn_id":"t1","tool_name":"Bash","tool_use_id":"u1","tool_input":{"command":"echo marker >> report.txt"},"cwd":"/tmp"}`

var disabledCodexHeaders = map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract}

// TestManagedHookSocketAnswersADisabledConnectorAllowWithoutAScan is
// rel-1-0-6:GAP-0325 on Linux and macOS: with
// guardrail.connectors.codex.enabled false the guardian enrolls nobody for
// Codex, and a Codex hook that still runs (a session started before the
// change) was refused as an unenrolled account, so every call was blocked.
// It now reaches the Codex route, which answers allow without a scan.
// Enabled connectors, root under enrollment.root: deny, inspect routes and
// the Codex notifier keep the enrollment check, so a user cannot use a
// disabled connector to skip it.
func TestManagedHookSocketAnswersADisabledConnectorAllowWithoutAScan(t *testing.T) {
	alice := managedHookPeer{UID: 1001, Name: "alice"}
	for rep := 1; rep <= 3; rep++ {
		handler := disabledConnectorSocketAPI(t, false, config.EnterpriseEnrollmentConfig{UnenrolledUsers: "deny"})
		w := postDisabledConnectorHook(t, handler, "/api/v1/codex/hook", disabledCodexPreToolUse, disabledCodexHeaders, alice)
		if w.Code != http.StatusOK {
			t.Fatalf("rep %d: disabled codex hook status %d body %s", rep, w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("rep %d: decode %s: %v", rep, w.Body.String(), err)
		}
		if out["action"] != "allow" || strings.Contains(w.Body.String(), managedHookReasonUIDUnregistered) {
			t.Fatalf("rep %d: a disabled connector must be answered allow without a scan: %s", rep, w.Body.String())
		}
	}

	handler := disabledConnectorSocketAPI(t, false, config.EnterpriseEnrollmentConfig{})
	// An enabled connector keeps the enrollment check.
	w := postDisabledConnectorHook(t, handler, "/api/v1/claude-code/hook",
		`{"hook_event_name":"UserPromptSubmit","session_id":"s1","prompt":"hello","cwd":"/tmp"}`, nil, alice)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), managedHookReasonUIDUnregistered) {
		t.Fatalf("an enabled connector's unenrolled caller must stay refused: %d %s", w.Code, w.Body.String())
	}
	// The Codex notifier and an inspect route naming Codex have no
	// allow-without-scan answer and keep the check.
	w = postDisabledConnectorHook(t, handler, "/api/v1/codex/notify", `{"type":"agent-turn-complete"}`, nil, alice)
	if w.Code != http.StatusForbidden {
		t.Fatalf("the codex notifier must keep the enrollment check: %d %s", w.Code, w.Body.String())
	}
	w = postDisabledConnectorHook(t, handler, "/api/v1/inspect/tool", `{"tool":"Bash","args":{"command":"ls"}}`,
		map[string]string{"X-DefenseClaw-Connector": "codex"}, alice)
	if w.Code != http.StatusForbidden {
		t.Fatalf("an inspect route must keep the enrollment check for a disabled connector: %d %s", w.Code, w.Body.String())
	}
	// enrollment.root: deny still refuses root.
	rootDeny := disabledConnectorSocketAPI(t, false, config.EnterpriseEnrollmentConfig{Root: config.EnterpriseRootDeny})
	w = postDisabledConnectorHook(t, rootDeny, "/api/v1/codex/hook", disabledCodexPreToolUse, disabledCodexHeaders, managedHookPeer{UID: 0, Name: "root"})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), managedHookReasonRootDenied) {
		t.Fatalf("root deny must hold for a disabled connector: %d %s", w.Code, w.Body.String())
	}

	// Enabled again, the same unenrolled caller is refused: the pass-through
	// follows the config, not a sticky state.
	enabled := disabledConnectorSocketAPI(t, true, config.EnterpriseEnrollmentConfig{})
	w = postDisabledConnectorHook(t, enabled, "/api/v1/codex/hook", disabledCodexPreToolUse, disabledCodexHeaders, alice)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), managedHookReasonUIDUnregistered) {
		t.Fatalf("an enabled codex keeps the enrollment check: %d %s", w.Code, w.Body.String())
	}
}

func TestManagedHookAuthorizerDisabledConnectorDecision(t *testing.T) {
	empty := func() (managedHookLedger, error) { return managedHookLedger{}, nil }
	carol := managedHookPeer{UID: 3001, Name: "carol"}
	z := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{UnenrolledUsers: "deny", UnverifiedVersions: "refuse"}, nil, empty)
	if d := z.decideFor(carol, "codex", "cli", true); !d.Allow || !d.Disabled {
		t.Fatalf("disabled connector decision = %+v, want allow with Disabled", d)
	}
	if d := z.decideFor(carol, "codex", "cli", false); d.Allow || d.Reason != managedHookReasonUIDUnregistered {
		t.Fatalf("enabled connector decision = %+v, want the enrollment refusal", d)
	}
	if d := z.decideFor(carol, "claudecode", "extension", true); d.Allow || d.Reason != managedHookReasonSurfaceUnverified {
		t.Fatalf("a refused surface stays refused for a disabled connector: %+v", d)
	}
	if d := z.decide(carol, "codex", "cli"); d.Allow {
		t.Fatalf("decide never takes the disabled path: %+v", d)
	}
}
