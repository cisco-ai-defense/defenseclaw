// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// bootStubConnector embeds stubConnector (full connector.Connector) and lets a
// test inject a Setup error plus count lifecycle calls, so the multi-connector
// boot loop's failure-isolation behavior can be exercised without touching the
// real connector registry.
type bootStubConnector struct {
	stubConnector
	setupErr      error
	setupCalls    int
	teardownCalls int
	credsSet      bool
}

func (b *bootStubConnector) Setup(context.Context, connector.SetupOpts) error {
	b.setupCalls++
	return b.setupErr
}

func (b *bootStubConnector) Teardown(context.Context, connector.SetupOpts) error {
	b.teardownCalls++
	return nil
}

func (b *bootStubConnector) SetCredentials(string, string) { b.credsSet = true }

func multiBootSidecar(t *testing.T) *Sidecar {
	t.Helper()
	return &Sidecar{
		cfg: &config.Config{
			DataDir:   t.TempDir(),
			Guardrail: config.GuardrailConfig{},
		},
	}
}

// TestSetupOneConnector_SetupErrorReturnsWithoutRollback verifies that a
// Setup() failure surfaces as an error and does NOT trigger a teardown: there
// is nothing to roll back because Setup never reached a verified state.
func TestSetupOneConnector_SetupErrorReturnsWithoutRollback(t *testing.T) {
	s := multiBootSidecar(t)
	conn := &bootStubConnector{stubConnector: stubConnector{name: "codex"}, setupErr: errors.New("boom")}
	cache := guardrail.NewRulePackCache()

	opts := s.connectorSetupOpts(conn, "tok", "127.0.0.1:0", "127.0.0.1:0")
	err := s.setupOneConnector(context.Background(), conn, opts, "master", cache)
	if err == nil {
		t.Fatal("expected error from failing Setup, got nil")
	}
	if conn.setupCalls != 1 {
		t.Errorf("setupCalls=%d, want 1", conn.setupCalls)
	}
	if conn.teardownCalls != 0 {
		t.Errorf("Setup failure must not roll back; teardownCalls=%d, want 0", conn.teardownCalls)
	}
	if !conn.credsSet {
		t.Error("credentials must be injected before Setup")
	}
}

// TestSetupOneConnector_SuccessNoTeardown confirms the happy path returns nil
// and leaves the connector installed (no teardown).
func TestSetupOneConnector_SuccessNoTeardown(t *testing.T) {
	s := multiBootSidecar(t)
	conn := &bootStubConnector{stubConnector: stubConnector{name: "cursor"}}
	cache := guardrail.NewRulePackCache()

	opts := s.connectorSetupOpts(conn, "tok", "127.0.0.1:0", "127.0.0.1:0")
	if err := s.setupOneConnector(context.Background(), conn, opts, "master", cache); err != nil {
		t.Fatalf("expected nil error on clean setup, got %v", err)
	}
	if conn.teardownCalls != 0 {
		t.Errorf("clean setup must not tear down; teardownCalls=%d, want 0", conn.teardownCalls)
	}
}

// TestSetupConnectorsIsolated_AllSucceed verifies every connector that sets up
// cleanly appears in the returned set, in input order.
func TestSetupConnectorsIsolated_AllSucceed(t *testing.T) {
	s := multiBootSidecar(t)
	conns := []connector.Connector{
		&bootStubConnector{stubConnector: stubConnector{name: "codex"}},
		&bootStubConnector{stubConnector: stubConnector{name: "cursor"}},
	}
	got := s.setupConnectorsIsolated(context.Background(), conns, "tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache())
	want := []string{"codex", "cursor"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("succeeded=%v, want %v", got, want)
	}
}

// TestSetupConnectorsIsolated_DN1_MiddleFailsOthersSurvive is the DN1
// failure-isolation tripwire: with three connectors where the MIDDLE one fails
// Setup, the other two must still come up. A regression that aborted the loop
// on first failure (or let a panic cascade) would drop the survivors here.
func TestSetupConnectorsIsolated_DN1_MiddleFailsOthersSurvive(t *testing.T) {
	s := multiBootSidecar(t)
	first := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	middle := &bootStubConnector{stubConnector: stubConnector{name: "cursor"}, setupErr: errors.New("middle boom")}
	last := &bootStubConnector{stubConnector: stubConnector{name: "windsurf"}}

	got := s.setupConnectorsIsolated(
		context.Background(),
		[]connector.Connector{first, middle, last},
		"tok", "127.0.0.1:0", "127.0.0.1:0", "master",
		guardrail.NewRulePackCache(),
	)

	want := []string{"codex", "windsurf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("survivors=%v, want %v (middle connector failure must not cascade)", got, want)
	}
	// Every connector's Setup must have been attempted — the failing one in
	// the middle must not short-circuit the connector after it.
	if first.setupCalls != 1 || middle.setupCalls != 1 || last.setupCalls != 1 {
		t.Errorf("setupCalls codex=%d cursor=%d windsurf=%d, want 1/1/1",
			first.setupCalls, middle.setupCalls, last.setupCalls)
	}
}

// TestSetupConnectorsIsolated_AllFailReturnsEmpty confirms that when every
// connector fails the result is empty (the caller turns this into a loud boot
// failure rather than idling on a gateway that protects nothing).
func TestSetupConnectorsIsolated_AllFailReturnsEmpty(t *testing.T) {
	s := multiBootSidecar(t)
	conns := []connector.Connector{
		&bootStubConnector{stubConnector: stubConnector{name: "codex"}, setupErr: errors.New("x")},
		&bootStubConnector{stubConnector: stubConnector{name: "cursor"}, setupErr: errors.New("y")},
	}
	got := s.setupConnectorsIsolated(context.Background(), conns, "tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache())
	if len(got) != 0 {
		t.Errorf("all-fail must yield empty survivor set, got %v", got)
	}
}

// TestConnectorSetupOpts_PerConnectorHookFailMode verifies the per-connector
// hook_fail_mode override flows into the SetupOpts via EffectiveHookFailModeFor
// — the global fail mode for connectors without an override, the override
// value for those that set one.
func TestConnectorSetupOpts_PerConnectorHookFailMode(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.Guardrail.HookFailMode = "open"
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"cursor": {HookFailMode: "closed"},
	}

	codexOpts := s.connectorSetupOpts(&bootStubConnector{stubConnector: stubConnector{name: "codex"}}, "tok", "a", "b")
	if codexOpts.HookFailMode != "open" {
		t.Errorf("codex HookFailMode=%q, want global %q", codexOpts.HookFailMode, "open")
	}
	cursorOpts := s.connectorSetupOpts(&bootStubConnector{stubConnector: stubConnector{name: "cursor"}}, "tok", "a", "b")
	if cursorOpts.HookFailMode != "closed" {
		t.Errorf("cursor HookFailMode=%q, want override %q", cursorOpts.HookFailMode, "closed")
	}
}

// TestRunGuardrailMulti_FailFastProxyGuard verifies that a proxy-binding
// connector in a multi-connector set aborts boot with a clear error before any
// connector is set up. Multi-connector mode is hook-only: a single process can
// bind only one guardrail proxy port, so openclaw alongside codex is a config
// error we surface loudly.
func TestRunGuardrailMulti_FailFastProxyGuard(t *testing.T) {
	s := &Sidecar{
		cfg: &config.Config{
			DataDir: t.TempDir(),
			Guardrail: config.GuardrailConfig{
				Enabled: true,
				Connectors: map[string]config.PerConnectorGuardrailConfig{
					"codex":    {},
					"openclaw": {}, // proxy-binding — must trip the guard
				},
			},
		},
		health: NewSidecarHealth(),
		router: &EventRouter{},
	}

	err := s.runGuardrailMulti(context.Background())
	if err == nil {
		t.Fatal("expected fail-fast proxy-guard error, got nil")
	}
	if want := "requires a proxy binding"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not mention %q", err.Error(), want)
	}
}
