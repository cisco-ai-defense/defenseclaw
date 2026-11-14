// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookcli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

const foreignGuardHookBinary = "/opt/defenseclaw/bin/defenseclaw-hook"

type foreignGuardFixture struct {
	home    string
	project string
	summary *enterprisepolicy.PublicPolicy
	loadErr error
	// process is the agent process identity the guard sees ("" unknown).
	process string
	// cleanMirror is whether the gateway's clean-session entry of the agent
	// process is present and trusted (hookForeignGuardCleanMirror).
	cleanMirror bool
}

// newPortableForeignGuardFixture is the fixture for tests that use only
// foreign hook entries, which read the same on every OS.
func newPortableForeignGuardFixture(t *testing.T, mode string) *foreignGuardFixture {
	t.Helper()
	fixture := &foreignGuardFixture{home: t.TempDir()}
	// The guard scan reads the agent environment: on Windows Devin keeps its
	// user config under %APPDATA%, which must be the fixture home, not the
	// account that runs the tests (GAP-0887).
	t.Setenv("APPDATA", filepath.Join(fixture.home, "AppData", "Roaming"))
	fixture.project = filepath.Join(fixture.home, "work", "repo")
	if err := os.MkdirAll(filepath.Join(fixture.project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixture.summary = &enterprisepolicy.PublicPolicy{
		SchemaVersion: 1,
		HookBinary:    foreignGuardHookBinary,
		Connectors: map[string]enterprisepolicy.PublicConnectorPolicy{
			"cursor": {Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: mode, Guard: true},
		},
	}
	previousPath, previousLoad := HookForeignGuardSummaryPath, HookForeignGuardLoad
	previousAccountHome, previousEnvHomes := HookForeignGuardAccountHome, HookForeignGuardEnvHomes
	previousProcess := HookForeignGuardAgentProcess
	previousExchange := HookForeignGuardExchange
	previousMirror, previousFailsOpen := HookForeignGuardCleanMirror, HookForeignGuardOutageFailsOpen
	HookForeignGuardCleanMirror = func(enterprisepolicy.SessionKey) error {
		if fixture.cleanMirror {
			return nil
		}
		return os.ErrNotExist
	}
	HookForeignGuardOutageFailsOpen = func(string, string) bool { return false }
	gatewayState := t.TempDir()
	HookForeignGuardSummaryPath = func() (string, bool) { return "/etc/defenseclaw/machine-policy.json", true }
	HookForeignGuardLoad = func(string) (*enterprisepolicy.PublicPolicy, error) {
		if fixture.loadErr != nil {
			return nil, fixture.loadErr
		}
		if fixture.summary == nil {
			return nil, enterprisepolicy.ErrNoPublicPolicy
		}
		return fixture.summary, nil
	}
	HookForeignGuardAccountHome = func() string { return fixture.home }
	HookForeignGuardEnvHomes = func() []string { return nil }
	HookForeignGuardAgentProcess = func() string { return fixture.process }
	HookForeignGuardExchange = func(_ string, _ string, _, _ time.Time, exchange enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
		if exchange.Key.Session == "" && exchange.Key.Process == "" {
			return exchange.Decision, nil
		}
		return enterprisepolicy.ApplyForeignHookSession(enterprisepolicy.SessionUpdate{
			StateDir: filepath.Join(gatewayState, exchange.Key.Connector),
			Key:      exchange.Key, SessionStart: exchange.SessionStart, Decision: exchange.Decision,
		}), nil
	}
	t.Cleanup(func() {
		HookForeignGuardSummaryPath, HookForeignGuardLoad = previousPath, previousLoad
		HookForeignGuardAccountHome, HookForeignGuardEnvHomes = previousAccountHome, previousEnvHomes
		HookForeignGuardAgentProcess = previousProcess
		HookForeignGuardExchange = previousExchange
		HookForeignGuardCleanMirror, HookForeignGuardOutageFailsOpen = previousMirror, previousFailsOpen
	})
	return fixture
}

func (f *foreignGuardFixture) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
