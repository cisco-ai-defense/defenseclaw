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

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hookedServices runs a callback before the fake service manager stops or
// starts a unit, to change inputs in the middle of a transaction.
type hookedServices struct {
	*fakeServices
	onStop  func(unit string)
	onStart func(unit string)
}

func (s *hookedServices) Stop(ctx context.Context, u Unit) error {
	if s.onStop != nil {
		s.onStop(u.Name)
	}
	return s.fakeServices.Stop(ctx, u)
}

func (s *hookedServices) Start(ctx context.Context, u Unit) error {
	if s.onStart != nil {
		s.onStart(u.Name)
	}
	return s.fakeServices.Start(ctx, u)
}

func unitOf(goos, kind string) string {
	for _, unit := range newServiceManager(&Env{GOOS: goos}).Units() {
		if unit.Kind == kind {
			return unit.Name
		}
	}
	return ""
}

// once returns a hook that writes data to canonical the first time unit is
// stopped or started.
func writeOnce(t *testing.T, h *testHost, unit, canonical string, data []byte) func(string) {
	done := false
	return func(name string) {
		if name != unit || done {
			return
		}
		done = true
		if err := os.WriteFile(h.env.P(canonical), data, 0o640); err != nil {
			t.Errorf("write %s: %v", canonical, err)
		}
	}
}

// An administrator (or configuration management) writes config.yaml while
// another lifecycle run holds the lock. The run used to write the bytes it
// had planned from back over the change (or leave a later write on disk
// unapplied, with the apply trigger stopped), and the next ensure was a
// no-op: the change was silently lost. The run now keeps the newer bytes and
// applies them in a follow-up transaction before it releases the lock. A
// run given --config is no different: it wrote its own file over one
// written in place while it ran, and the later writer lost (GAP-0745).
func TestConfigWrittenDuringATransactionIsApplied(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, moment := range []string{"quiesce", "activation", "quiesce-with-config-flag"} {
			t.Run(goos+"-"+moment, func(t *testing.T) {
				h := newTestHost(t, goos)
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
				edited := []byte(strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1))
				hooked := &hookedServices{fakeServices: h.services}
				if strings.HasPrefix(moment, "quiesce") {
					hooked.onStop = writeOnce(t, h, unitOf(goos, "enumerator"), h.env.Layout.ConfigPath, edited)
				} else {
					hooked.onStart = writeOnce(t, h, unitOf(goos, "gateway"), h.env.Layout.ConfigPath, edited)
				}
				h.env.Services = hooked
				opts := Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")}
				if moment == "quiesce-with-config-flag" {
					opts.ConfigFile = filepath.Join(t.TempDir(), "pushed.yaml")
					if err := os.WriteFile(opts.ConfigFile, append(DefaultConfig(h.env.Layout), "# pushed\n"...), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				r := h.run(opts)
				requireOK(t, r)
				if !strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
					t.Fatal("the transaction wrote its planned config over the administrator's change")
				}
				record, _ := h.env.loadDeployment()
				if record.ConfigSHA256 != sha256Bytes(edited) || record.ProductVersion != "1.0.1" {
					t.Fatalf("the change is not applied: config %s version %s", record.ConfigSHA256[:8], record.ProductVersion)
				}
				if !hasWarning(r, "input_changed") {
					t.Fatalf("the result does not say a follow-up applied the change: %+v", r.Warnings)
				}
				again := h.run(Options{Action: ActionEnsure})
				requireOK(t, again)
				if !again.Noop {
					t.Fatal("ensure after the follow-up is not a no-op")
				}
			})
		}
	}
}

// A protected credential written during a transaction is applied the same
// way.
func TestSecretWrittenDuringATransactionIsApplied(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	secret := filepath.Join(h.env.Layout.SecretsDir, "ai-defense-api-key")
	h.env.Services = &hookedServices{fakeServices: h.services, onStop: writeOnce(t, h, unitEnumerator, secret, []byte("rotated"))}
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")}))
	_, secretsSHA, err := h.env.listSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if record, _ := h.env.loadDeployment(); record.SecretsSHA256 != secretsSHA {
		t.Fatal("the credential written during the transaction is not applied")
	}
}

// After a failed transaction the change is neither reverted by the rollback
// nor lost: the apply trigger is started so it runs ensure once this run
// ends.
func TestConfigWrittenDuringAFailedTransactionRetriggersApply(t *testing.T) {
	for goos, trigger := range map[string]string{
		"linux":  "systemctl start --no-block " + unitApplyService,
		"darwin": "launchctl kickstart system/" + labelApply,
	} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			edited := []byte(strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1))
			h.env.Services = &hookedServices{fakeServices: h.services, onStop: writeOnce(t, h, unitOf(goos, "enumerator"), h.env.Layout.ConfigPath, edited)}
			h.healthy = false
			failed := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
			requireError(t, failed, codeActivate)
			if !strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
				t.Fatal("the rollback put the previous config.yaml back over the administrator's change")
			}
			found := false
			for _, call := range h.runner.calls {
				if call == trigger {
					found = true
				}
			}
			if !found || !hasWarning(failed, "input_changed") {
				t.Fatalf("the apply trigger was not started (%v): %+v", found, failed.Warnings)
			}
		})
	}
}

// The documented MDM flow: edit E1 is written into config.yaml and the apply
// trigger runs ensure; E2 is written while that run is under way and the
// run then fails. The rollback reverts to the last applied config for its
// restart, keeps E1 (the edit it checked) as the rejected file rather than
// E2 (which nothing checked), puts E2 back afterwards and starts the apply
// trigger, so E2 gets its own transaction instead of being reported as
// rejected and dropped.
func TestConfigPushedDuringAFailedInPlaceEditIsAppliedNext(t *testing.T) {
	for goos, trigger := range map[string]string{
		"linux":  "systemctl start --no-block " + unitApplyService,
		"darwin": "launchctl kickstart system/" + labelApply,
	} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			applied := h.read(h.env.Layout.ConfigPath)
			first := []byte(strings.Replace(applied, "mode: observe", "mode: action", 1))
			second := []byte(strings.Replace(applied, "mode: observe", "mode: action", 1) + "# second push\n")
			if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), first, 0o640); err != nil {
				t.Fatal(err)
			}
			h.env.Services = &hookedServices{fakeServices: h.services, onStop: writeOnce(t, h, unitOf(goos, "enumerator"), h.env.Layout.ConfigPath, second)}
			h.healthy = false
			failed := h.run(Options{Action: ActionEnsure, Reason: "path"})
			requireError(t, failed, codeActivate)
			if got := h.read(h.env.Layout.ConfigPath); got != string(second) {
				t.Fatalf("config.yaml after the rollback is not the newer push:\n%s", got)
			}
			if kept, err := os.ReadFile(h.env.rejectedConfigPath()); err != nil || string(kept) != string(first) {
				t.Fatalf("rejected-config.yaml = %q (%v), want the edit this run checked", kept, err)
			}
			if h.env.rejectedConfigProblem() != "" {
				t.Fatal("status reports the newer push as rejected")
			}
			found := false
			for _, call := range h.runner.calls {
				if call == trigger {
					found = true
				}
			}
			if !found || !hasWarning(failed, "input_changed") {
				t.Fatalf("the apply trigger was not started for the newer push (%v): %+v", found, failed.Warnings)
			}
			// The retriggered run applies the newer push.
			h.healthy = true
			h.env.Services = h.services
			requireOK(t, h.run(Options{Action: ActionEnsure, Reason: "path"}))
			if record, _ := h.env.loadDeployment(); record.ConfigSHA256 != sha256Bytes(second) {
				t.Fatal("the newer push was not applied by the next run")
			}
		})
	}
}

// A follow-up transaction describes the deployment again; a standing
// warning such as a failed oneshot is reported once in the one result, not
// once per pass.
func TestAFollowUpTransactionReportsEachWarningOnce(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	// The guardian reconcile oneshot: a committing run clears a failed apply
	// or verify oneshot (GAP-0423), not this one.
	h.services.failed[unitGuardianOneshot] = true
	edited := []byte(strings.Replace(h.read(h.env.Layout.ConfigPath), "mode: observe", "mode: action", 1))
	h.env.Services = &hookedServices{fakeServices: h.services, onStart: writeOnce(t, h, unitOf("linux", "gateway"), h.env.Layout.ConfigPath, edited)}
	r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")})
	requireOK(t, r)
	if !hasWarning(r, codeInputChanged) {
		t.Fatalf("premise: a follow-up transaction ran: %+v", r.Warnings)
	}
	count := 0
	for _, warning := range r.Warnings {
		if warning.Code == "unit_failed" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("unit_failed reported %d times: %+v", count, r.Warnings)
	}
}
