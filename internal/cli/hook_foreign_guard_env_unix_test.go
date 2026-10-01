// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The guardian's per-user worker runs without the user's session
// environment. A hook that ran with COPILOT_HOME (or XDG_CONFIG_HOME,
// CODEX_HOME, ...) records the redirect, and the worker's next cleanup
// removes the foreign hook from the redirected user config too.
func TestForeignHookGuardRecordsRedirectsTheGuardianCleans(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.guard("copilot")
	custom := filepath.Join(fixture.home, "alt-copilot")
	foreign := filepath.Join(custom, "hooks", "rewrite.json")
	fixture.write(t, foreign, `{"hooks": {"preToolUse": [{"bash": "./rewrite.sh"}]}}`)

	t.Setenv("COPILOT_HOME", custom)
	if call := fixture.runEvent(t, "copilot", "preToolUse", "sessionId", ""); !strings.Contains(call.ManagedRuntimeFailure, foreign) {
		t.Fatalf("the hook sees COPILOT_HOME and denies: %q", call.ManagedRuntimeFailure)
	}
	redirects, err := enterprisepolicy.LoadEnvRedirects(fixture.home, "copilot")
	if err != nil || len(redirects) != 1 || redirects[0].Vars["COPILOT_HOME"] != custom {
		t.Fatalf("the hook must record the redirect for the guardian: %+v %v", redirects, err)
	}

	// The worker's own environment has no COPILOT_HOME.
	t.Setenv("COPILOT_HOME", "")
	reports := runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{
		Home: fixture.home,
		ForeignCleanup: []enterpriseHookWorkerForeignCleanup{{
			Connector:  "copilot",
			HookBinary: foreignGuardHookBinary,
			Policy:     fixture.summary.Connectors["copilot"],
		}},
	}, time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))
	report := reports["copilot"]
	if report.Error != "" || len(report.Removed) != 1 || report.Removed[0] != foreign {
		t.Fatalf("the worker must clean the redirected user config: %+v", report)
	}
	if data, _ := os.ReadFile(foreign); strings.Contains(string(data), "rewrite.sh") {
		t.Fatalf("the foreign hook is still registered: %s", data)
	}
	t.Setenv("COPILOT_HOME", custom)
	if call := fixture.runEvent(t, "copilot", "preToolUse", "sessionId", ""); call.ManagedRuntimeFailure != "" {
		t.Fatalf("with the hook removed the call allows: %q", call.ManagedRuntimeFailure)
	}
}

// A corrupt redirect record is reported, and the default locations are
// still cleaned.
func TestWorkerForeignCleanupReportsAnUnreadableRedirectRecord(t *testing.T) {
	home := t.TempDir()
	hooks := filepath.Join(home, ".cursor", "hooks.json")
	for path, body := range map[string]string{
		hooks:                                `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`,
		enterprisepolicy.EnvRecordPath(home): "{broken",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reports := runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{
		Home: home,
		ForeignCleanup: []enterpriseHookWorkerForeignCleanup{{
			Connector:  "cursor",
			HookBinary: foreignGuardHookBinary,
			Policy:     enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true},
		}},
	}, time.Now())
	report := reports["cursor"]
	if len(report.Removed) != 1 || !strings.Contains(report.Error, enterprisepolicy.EnvRecordPath(home)) {
		t.Fatalf("the default location is cleaned and the bad record reported: %+v", report)
	}
}
