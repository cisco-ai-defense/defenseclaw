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

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// A daemon below the floor contract (1.0.2 and earlier send no contract)
// adopts only part of the floor policy/current gives and would mark it
// confirmed. The managed gateway names the mismatch and fails closed: no new
// sandbox, no bind, no renewal of a running one, no floor to confirm and no
// relayed call. A revocation, a stopped report, a deletion and the settings
// still reach it, and a current daemon is unaffected (GAP-0182).
func TestSandboxAuthorityRefusesOutdatedDaemon(t *testing.T) {
	// One account makes many policy calls here; the per-account budget is
	// not under test.
	prevBudget := sandboxBudgetLimits[sandboxBudgetPolicy]
	sandboxBudgetLimits[sandboxBudgetPolicy] = sandboxBudgetLimit{Rate: 1000, Burst: 1000, InFlight: 8}
	t.Cleanup(func() { sandboxBudgetLimits[sandboxBudgetPolicy] = prevBudget })
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	var mu sync.Mutex
	var refused []string
	prev := sandboxRecordResolveRefused
	sandboxRecordResolveRefused = func(_ *APIServer, attempt sandboxreg.Registration, reason string) {
		mu.Lock()
		defer mu.Unlock()
		refused = append(refused, attempt.Profile+":"+reason)
	}
	t.Cleanup(func() { sandboxRecordResolveRefused = prev })

	running := f.live(sbxAlice, 1)
	kept := f.live(sbxAlice, 2)
	revoked := f.live(sbxAlice, 3)
	pending := f.resolve(sbxAlice, claudeResolve())
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.store.Revoke(sbxAlice.UID, revoked.Registration.ID, "regrouped"); err != nil {
		t.Fatal(err)
	}

	isOutdated := func(what string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusForbidden || errorReason(t, rec) != sandboxrelay.ReasonDaemonOutdated ||
			!strings.Contains(rec.Body.String(), "older DefenseClaw version") {
			t.Fatalf("%s from an outdated daemon: %d %s", what, rec.Code, rec.Body.String())
		}
	}
	with := func(old map[string]string, extra ...string) map[string]string {
		h := map[string]string{}
		for k, v := range old {
			h[k] = v
		}
		for i := 0; i+1 < len(extra); i += 2 {
			h[extra[i]] = extra[i+1]
		}
		return h
	}
	for _, old := range []map[string]string{
		{sandboxrelay.DaemonContractHeader: ""},
		{sandboxrelay.DaemonContractHeader: "1"},
		{sandboxrelay.DaemonContractHeader: "two"},
	} {
		isOutdated("resolve", f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(),
			with(old, sandboxrelay.ConnectorHeader, "claudecode")))
		isOutdated("bind", f.do(sbxAlice, http.MethodPost, sandboxrelay.PathRegistrations+pending.Registration.ID+sandboxrelay.RegistrationBindSub,
			sandboxrelay.BindRequest{V: 1, SandboxName: "dc-claude-9", SandboxID: "sbx-9", BindingID: "sb_" + strings.Repeat("9", 32)}, old))
		isOutdated("running report", f.do(sbxAlice, http.MethodPost, sandboxrelay.PathRegistrations+running.Registration.ID+sandboxrelay.RegistrationStateSub,
			sandboxrelay.StateReport{V: 1, Running: true}, old))
		isOutdated("policy/current", f.do(sbxAlice, http.MethodGet, sandboxrelay.PathPolicyCurrent+"?registration="+running.Registration.ID, nil, old))
		isOutdated("relayed hook", f.hook(sbxAlice, running.Registration.ID, "claudecode", old))
		isOutdated("packs", f.do(sbxAlice, http.MethodGet, sandboxrelay.PathPolicyPacks, nil, with(old, sandboxrelay.ConnectorHeader, "claudecode")))
	}
	mu.Lock()
	if len(refused) != 3 || refused[0] != "contractors:"+sandboxrelay.ReasonDaemonOutdated {
		t.Fatalf("recorded resolve refusals: %v", refused)
	}
	mu.Unlock()

	old := map[string]string{sandboxrelay.DaemonContractHeader: ""}
	if rec := f.do(sbxAlice, http.MethodGet, sandboxrelay.PathSettings, nil, with(old, sandboxrelay.ConnectorHeader, "claudecode")); rec.Code != http.StatusOK {
		t.Fatalf("settings for an outdated daemon: %d %s", rec.Code, rec.Body.String())
	}
	// A revocation still reaches it, so it stops that sandbox.
	if rec := f.do(sbxAlice, http.MethodGet, sandboxrelay.PathPolicyCurrent+"?registration="+revoked.Registration.ID, nil, old); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"revoked":true`) {
		t.Fatalf("revocation for an outdated daemon: %d %s", rec.Code, rec.Body.String())
	}
	// A stopped report is recorded (the sandbox's hooks end at once) but
	// confirms nothing.
	isOutdated("stopped report", f.do(sbxAlice, http.MethodPost, sandboxrelay.PathRegistrations+kept.Registration.ID+sandboxrelay.RegistrationStateSub,
		sandboxrelay.StateReport{V: 1, Running: false}, old))
	if rec := f.hook(sbxAlice, kept.Registration.ID, "claudecode", nil); rec.Code != http.StatusForbidden ||
		errorReason(t, rec) != sandboxrelay.ReasonRegistrationStopped {
		t.Fatalf("hook after an outdated daemon reported its sandbox stopped: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathRegistrations+kept.Registration.ID+sandboxrelay.RegistrationDelSub, []byte(`{}`), old); rec.Code != http.StatusNoContent {
		t.Fatalf("deletion from an outdated daemon: %d %s", rec.Code, rec.Body.String())
	}

	// The refusals changed nothing for a current daemon.
	if code, cur := f.current(sbxAlice, running.Registration.ID); code != http.StatusOK || cur.Floor == nil || cur.Revoked {
		t.Fatalf("policy/current for a current daemon: %d %+v", code, cur)
	}
	if code, _ := f.report(sbxAlice, running.Registration.ID, true); code != http.StatusOK {
		t.Fatalf("running report from a current daemon: %d", code)
	}
	if rec := f.hook(sbxAlice, running.Registration.ID, "claudecode", nil); rec.Code != http.StatusOK {
		t.Fatalf("hook from a current daemon: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.bind(sbxAlice, pending.Registration.ID, 9); rec.Code != http.StatusOK {
		t.Fatalf("bind from a current daemon: %d %s", rec.Code, rec.Body.String())
	}
}

// The routes a daemon below the floor contract still reaches.
func TestSandboxOutdatedDaemonRoute(t *testing.T) {
	reg := sandboxrelay.PathRegistrations + "reg-1"
	for path, want := range map[string]bool{
		sandboxrelay.PathSettings:                  true,
		sandboxrelay.PathEvents:                    true,
		sandboxrelay.PathPolicyResolve:             true,
		sandboxrelay.PathPolicyCurrent:             true,
		reg + sandboxrelay.RegistrationStateSub:    true,
		reg + sandboxrelay.RegistrationDelSub:      true,
		reg + sandboxrelay.RegistrationBindSub:     false,
		sandboxrelay.PathPolicyExplain:             false,
		sandboxrelay.PathPolicyTest:                false,
		sandboxrelay.PathPolicyPacks:               false,
		sandboxrelay.PathDecisions:                 false,
		sandboxrelay.PathHookPrefix + "claudecode": false,
		sandboxrelay.PathNotifyPrefix + "codex":    false,
		sandboxrelay.PathInspectPrefix + "tool":    false,
		sandboxrelay.PathOTLPPrefix + "logs":       false,
	} {
		if got := sandboxOutdatedDaemonRoute(path); got != want {
			t.Errorf("sandboxOutdatedDaemonRoute(%q) = %v, want %v", path, got, want)
		}
	}
}
