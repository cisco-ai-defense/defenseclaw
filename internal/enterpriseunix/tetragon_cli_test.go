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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

var tetragonDropinPath = filepath.Join("/etc/systemd/system", unitSensorHelper+".d", dropinTetragon)

// Marker policy names, in the exact shape the helper records.
var recordedTetragonPolicies = []string{"defenseclaw-controls-0a1b2c3d", "defenseclaw-observe-11112222"}

// tetragonTestConfig is the default standalone config with an
// enterprise.tetragon block, two enrolled connectors (claudecode in action
// mode) and, with planeC, AI Discovery Plane C.
func tetragonTestConfig(t *testing.T, h *testHost, block string, planeC bool) string {
	t.Helper()
	body := string(DefaultConfig(h.env.Layout))
	if block != "" {
		body = strings.Replace(body, "enterprise:\n  profile: standalone\n", "enterprise:\n  profile: standalone\n  tetragon:\n"+block, 1)
	}
	body += "  connectors:\n    claudecode:\n      mode: action\n    codex: {}\n"
	if planeC {
		body += "ai_discovery:\n  runtime:\n    enabled: true\n    enable_host_plane: true\n"
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func expectedTetragonDropin(mode, burnIn, ack, connectors string, extra ...string) string {
	out := "# Written by the DefenseClaw enterprise lifecycle. Do not edit.\n" +
		"# defenseclaw-derived: enterprise.tetragon kernel_policy=" + kernelpolicy.Digest() + "\n" +
		"[Service]\n" +
		"Environment=DEFENSECLAW_SENSOR_TETRAGON_MODE=" + mode + "\n" +
		"Environment=DEFENSECLAW_SENSOR_TETRAGON_BURN_IN=" + burnIn + "\n" +
		"Environment=DEFENSECLAW_SENSOR_TETRAGON_ENFORCE_ACK=" + ack + "\n" +
		"Environment=DEFENSECLAW_SENSOR_TETRAGON_ENFORCE_CONNECTORS=" + connectors + "\n"
	for _, line := range extra {
		out += "Environment=" + line + "\n"
	}
	return out
}

func (h *testHost) recordTetragonPolicies(names ...string) {
	h.t.Helper()
	writeHostFile(h.t, h, filepath.Join(kernelpolicy.DefaultStateDir, "tetragon-loaded"), strings.Join(names, "\n")+"\n")
}

func (h *testHost) writeTetragonState(state kernelpolicy.FileState) {
	h.t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		h.t.Fatal(err)
	}
	writeHostFile(h.t, h, filepath.Join(kernelpolicy.DefaultStateDir, "tetragon-state.json"), string(data))
}

// tetragonHelperRunner answers the sensor helper's --tetragon-cleanup the way
// the helper does: it deletes the recorded names it can, prints each, and
// empties the record of the ones it removed.
type tetragonHelperRunner struct {
	Runner
	h *testHost
	// check is the exit code of --tetragon-cleanup --check; exit the one of
	// the cleanup, which keeps the names in keep.
	check, exit int
	keep        []string

	mu    sync.Mutex
	calls []string
	// binary is the helper's content and stopped whether its unit was
	// stopped, both when the cleanup ran.
	binary  string
	stopped bool
}

func (r *tetragonHelperRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if filepath.Base(name) != binSensorHelper || len(args) == 0 || args[0] != "--tetragon-cleanup" {
		return r.Runner.Run(ctx, name, args...)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, strings.Join(args, " "))
	if len(args) == 2 {
		if r.check != 0 {
			return CommandResult{ExitCode: r.check}, errors.New("flag provided but not defined: -tetragon-cleanup")
		}
		return CommandResult{Stdout: []byte("tetragon-cleanup: supported\n")}, nil
	}
	data, _ := os.ReadFile(name)
	r.binary, r.stopped = string(data), !r.h.services.isActive(unitSensorHelper)
	recorded, _ := r.h.env.recordedKernelPolicies()
	var out bytes.Buffer
	for _, policy := range recorded {
		if !contains(r.keep, policy) {
			out.WriteString("removed " + policy + "\n")
		}
	}
	r.h.recordTetragonPolicies(r.keep...)
	if len(r.keep) == 0 {
		_ = os.WriteFile(r.h.env.P(filepath.Join(kernelpolicy.DefaultStateDir, "tetragon-loaded")), nil, 0o600)
	}
	if r.exit != 0 {
		return CommandResult{Stdout: out.Bytes(), ExitCode: r.exit}, errors.New("exit status")
	}
	return CommandResult{Stdout: out.Bytes()}, nil
}

func (r *tetragonHelperRunner) cleanupCalls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// The drop-in is rendered only for a block that differs from the default,
// carries the four variables, is recorded and verified like every rendered
// file, restarts the helper when it changes and leaves with the block.
func TestTetragonDropinFollowsTheBlock(t *testing.T) {
	h := newTestHost(t, "linux")
	payload := h.payload("1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: payload, ConfigFile: tetragonTestConfig(t, h, "", true)}))
	if exists(h.env.P(tetragonDropinPath)) {
		t.Fatal("an absent enterprise.tetragon rendered a drop-in")
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: tetragonTestConfig(t, h, "    mode: consume\n    burn_in: 168h\n    customer_events: agent\n    enforce_ack: []\n", true)}))
	if exists(h.env.P(tetragonDropinPath)) {
		t.Fatal("a block that spells out the defaults rendered a drop-in")
	}

	calls := len(h.services.calls)
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: tetragonTestConfig(t, h, "    mode: observe\n    burn_in: 48h\n", true)}))
	if got, want := h.read(tetragonDropinPath), expectedTetragonDropin("observe", "48h", "", ""); got != want {
		t.Fatalf("drop-in:\n%s\nwant:\n%s", got, want)
	}
	record, err := h.env.loadDeployment()
	if err != nil || record.Files[tetragonDropinPath] != sha256Bytes([]byte(h.read(tetragonDropinPath))) {
		t.Fatalf("the drop-in is not recorded: %v %v", record, err)
	}
	if mode := h.mode(tetragonDropinPath); mode != 0o644 {
		t.Fatalf("drop-in mode %04o", mode)
	}
	restarted := strings.Join(h.services.calls[calls:], "\n")
	if !strings.Contains(restarted, "stop "+unitSensorHelper) || !strings.Contains(restarted, "start "+unitSensorHelper) {
		t.Fatalf("a changed drop-in must restart the helper: %v", h.services.calls[calls:])
	}
	if !h.run(Options{Action: ActionEnsure}).Noop {
		t.Fatal("an unchanged block must settle to a no-op")
	}

	writeHostFile(t, h, tetragonDropinPath, expectedTetragonDropin("enforce", "0", "", "claudecode"))
	verify := h.run(Options{Action: ActionVerify})
	if verify.OK || !strings.Contains(messagesOf(verify.Errors, codeVerify), tetragonDropinPath+" was modified after install") {
		t.Fatalf("verify must flag an edited drop-in: %+v", verify.Errors)
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if got := h.read(tetragonDropinPath); !strings.Contains(got, "MODE=observe") {
		t.Fatalf("repair did not restore the drop-in: %s", got)
	}

	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: tetragonTestConfig(t, h, "", true)}))
	if exists(h.env.P(tetragonDropinPath)) {
		t.Fatal("removing the block left its drop-in behind")
	}
	if record, _ := h.env.loadDeployment(); record.Files[tetragonDropinPath] != "" {
		t.Fatal("the removed drop-in is still recorded")
	}
}

// MODE is the effective mode: Plane C off caps it at off. Only enrolled
// connectors whose guardrail is in action mode can be anchored for a deny,
// and only in enforce mode. Status names every cap.
func TestTetragonDropinAppliesTheCaps(t *testing.T) {
	digest := kernelpolicy.Digest()
	cases := []struct {
		name, block string
		planeC      bool
		dropin      string
		warnings    []string
		absent      []string
	}{
		{
			name: "plane c off", block: "    mode: observe\n", planeC: false,
			dropin: expectedTetragonDropin("off", "168h", "", ""), warnings: []string{config.TetragonReasonPlaneCOff},
		},
		{
			name: "approved enforce", block: "    mode: enforce\n    enforce_ack: " + digest + "\n", planeC: true,
			dropin:   expectedTetragonDropin("enforce", "168h", digest, "claudecode"),
			warnings: []string{kernelpolicy.WarnGuardrailObserve + ":codex"},
			absent:   []string{kernelpolicy.WarnEnforceAckMissing, kernelpolicy.WarnEnforceAckStale, kernelpolicy.WarnBurnInSkipped},
		},
		{
			name: "enforce without approval", block: "    mode: enforce\n    burn_in: 0\n", planeC: true,
			dropin:   expectedTetragonDropin("enforce", "0", "", "claudecode"),
			warnings: []string{kernelpolicy.WarnEnforceAckMissing, kernelpolicy.WarnBurnInSkipped},
		},
		{
			name: "stale approval", block: "    mode: enforce\n    enforce_ack: sha256:000000000000\n", planeC: true,
			dropin:   expectedTetragonDropin("enforce", "168h", "sha256:000000000000", "claudecode"),
			warnings: []string{kernelpolicy.WarnEnforceAckStale},
		},
		{
			name: "observe keeps an approval inert", block: "    mode: observe\n    enforce_ack: sha256:000000000000\n", planeC: true,
			dropin: expectedTetragonDropin("observe", "168h", "sha256:000000000000", ""),
			absent: []string{kernelpolicy.WarnEnforceAckStale, kernelpolicy.WarnGuardrailObserve + ":codex"},
		},
		{
			// A ring upgrade approves the old and the new build at once: the
			// list reaches the helper as a comma list and approves this build.
			name: "approval list", block: "    mode: enforce\n    enforce_ack: [sha256:000000000000, " + digest + "]\n", planeC: true,
			dropin: expectedTetragonDropin("enforce", "168h", "sha256:000000000000,"+digest, "claudecode"),
			absent: []string{kernelpolicy.WarnEnforceAckMissing, kernelpolicy.WarnEnforceAckStale},
		},
		{
			name: "approval list without this build", block: "    mode: enforce\n    enforce_ack:\n      - sha256:000000000000\n      - sha256:111111111111\n", planeC: true,
			dropin:   expectedTetragonDropin("enforce", "168h", "sha256:000000000000,sha256:111111111111", "claudecode"),
			warnings: []string{kernelpolicy.WarnEnforceAckStale},
		},
		{
			// customer_events alone is a written block; its variable appears
			// only when it is not the default.
			name: "customer events off", block: "    customer_events: off\n", planeC: true,
			dropin: expectedTetragonDropin("consume", "168h", "", "", envTetragonCustomerEvents+"=off"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: tetragonTestConfig(t, h, tc.block, tc.planeC)}))
			if got := h.read(tetragonDropinPath); got != tc.dropin {
				t.Fatalf("drop-in:\n%s\nwant:\n%s", got, tc.dropin)
			}
			status := h.run(Options{Action: ActionStatus})
			for _, code := range tc.warnings {
				if !hasWarning(status, code) {
					t.Fatalf("status lacks %s: %+v", code, status.Warnings)
				}
			}
			for _, code := range tc.absent {
				if hasWarning(status, code) {
					t.Fatalf("status warns %s: %+v", code, status.Warnings)
				}
			}
			if !status.OK {
				t.Fatalf("a cap must never fail status: %+v", status.Errors)
			}
		})
	}
}

// macOS accepts the block, renders nothing for it and says it ignores it.
func TestTetragonIsNotApplicableOnMacOS(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: tetragonTestConfig(t, h, "    mode: enforce\n", true)}))
	status := h.run(Options{Action: ActionStatus})
	if !hasWarning(status, config.TetragonReasonNotApplicable) || !status.OK {
		t.Fatalf("macOS status: ok=%v warnings=%+v", status.OK, status.Warnings)
	}
	plain := newTestHost(t, "darwin")
	requireOK(t, plain.run(Options{Action: ActionInstall, PayloadDir: plain.payload("1.0.0")}))
	if hasWarning(plain.run(Options{Action: ActionStatus}), config.TetragonReasonNotApplicable) {
		t.Fatal("a macOS config without the block must not warn")
	}
}

// Uninstall removes the policies the helper loaded with the helper, after
// it stopped and before its binary or state go, lists them, and then
// removes the helper's state. Without a record it runs nothing.
func TestUninstallRemovesTheTetragonPoliciesFirst(t *testing.T) {
	for _, purge := range []bool{false, true} {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		h.recordTetragonPolicies(recordedTetragonPolicies...)
		// The until-reboot pause the unit keeps across stops.
		writeHostFile(t, h, filepath.Join(kernelpolicy.DefaultRunDir, "tetragon-pause"), "{}\n")
		runner := &tetragonHelperRunner{Runner: h.runner, h: h}
		h.env.Runner = runner
		r := h.run(Options{Action: ActionUninstall, Purge: purge})
		requireOK(t, r)
		if got := runner.cleanupCalls(); !reflect.DeepEqual(got, []string{"--tetragon-cleanup --check", "--tetragon-cleanup"}) {
			t.Fatalf("purge=%v cleanup calls %v", purge, got)
		}
		if runner.binary != "defenseclaw-sensor-helper 1.0.0\n" || !runner.stopped {
			t.Fatalf("the cleanup must run with the installed helper after its unit stopped: binary %q stopped %v", runner.binary, runner.stopped)
		}
		if !strings.Contains(strings.Join(r.Changes, "\n"), kernelPolicyChange(recordedTetragonPolicies)) {
			t.Fatalf("the summary does not list the removed policies: %v", r.Changes)
		}
		if exists(h.env.P(kernelpolicy.DefaultStateDir)) {
			t.Fatal("the helper's state outlived the uninstall")
		}
		if exists(h.env.P(kernelpolicy.DefaultRunDir)) {
			t.Fatal("the helper's runtime directory (socket, until-reboot pause) outlived the uninstall")
		}
	}

	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	runner := &tetragonHelperRunner{Runner: h.runner, h: h}
	h.env.Runner = runner
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	if calls := runner.cleanupCalls(); len(calls) != 0 {
		t.Fatalf("nothing recorded, but the helper ran: %v", calls)
	}
}

// What the cleanup could not remove is a warning naming the policies and
// the manual removal; the record stays for a later helper. A customer
// Tetragon outage never fails the uninstall.
func TestUninstallKeepsTheRecordOfTetragonPoliciesItCouldNotRemove(t *testing.T) {
	cases := []struct {
		name   string
		runner func(h *testHost) *tetragonHelperRunner
		why    string
	}{
		{"tetragon down", func(h *testHost) *tetragonHelperRunner {
			return &tetragonHelperRunner{Runner: h.runner, h: h, exit: tetragonCleanupUnreachable, keep: recordedTetragonPolicies}
		}, "Tetragon did not answer"},
		{"older helper", func(h *testHost) *tetragonHelperRunner {
			return &tetragonHelperRunner{Runner: h.runner, h: h, check: 2}
		}, "cannot remove Tetragon policies"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.recordTetragonPolicies(recordedTetragonPolicies...)
			h.env.Runner = tc.runner(h)
			r := h.run(Options{Action: ActionUninstall})
			requireOK(t, r)
			got := messagesOf(r.Warnings, codeKernelPolicyOrphaned)
			if !strings.Contains(got, tc.why) || !strings.Contains(got, recordedTetragonPolicies[0]) || !strings.Contains(got, "tetra tracingpolicy delete") {
				t.Fatalf("warning: %q", got)
			}
			if names, _ := h.env.recordedKernelPolicies(); !reflect.DeepEqual(names, recordedTetragonPolicies) {
				t.Fatalf("the record of the policies left is gone: %v", names)
			}
		})
	}
}

// An uninstall that stops early because per-user hooks remain has stopped
// the helper too, so it still removes the helper's policies.
func TestUninstallThatKeepsTheBinariesStillRemovesTheTetragonPolicies(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.recordTetragonPolicies(recordedTetragonPolicies...)
	runner := &tetragonHelperRunner{h: h, Runner: removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		return CommandResult{ExitCode: 1, Stdout: []byte(`{"ok":false,"removed":0,"failed":["alice/codex: remove hook entries: permission denied"]}`)}, errors.New("exit 1")
	}}}
	h.env.Runner = runner
	r := h.run(Options{Action: ActionUninstall})
	requireError(t, r, codeUninstall)
	if got := runner.cleanupCalls(); len(got) != 2 {
		t.Fatalf("cleanup calls %v", got)
	}
	if !strings.Contains(strings.Join(r.Changes, "\n"), kernelPolicyChange(recordedTetragonPolicies)) {
		t.Fatalf("changes %v", r.Changes)
	}
}

// A rolled-back transaction removes the policies with the transaction's
// helper, after it stopped and before the previous binaries come back.
func TestRollbackRemovesTheTetragonPoliciesBeforeRestoring(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	fault := filepath.Join(h.env.Layout.LifecycleDir, testFaultFileName)
	writeHostFile(t, h, fault, testFaultAfterServices+"\n")
	if err := os.Chmod(h.env.P(fault), 0o600); err != nil {
		t.Fatal(err)
	}
	h.owners[h.env.P(fault)] = [2]int{0, 0}
	h.recordTetragonPolicies(recordedTetragonPolicies...)
	runner := &tetragonHelperRunner{Runner: h.runner, h: h}
	h.env.Runner = runner
	r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
	requireError(t, r, codeLifecycleTestFault)
	if runner.binary != "defenseclaw-sensor-helper 2.0.0\n" || !runner.stopped {
		t.Fatalf("the rollback cleanup must run with the transaction's helper after it stopped: binary %q stopped %v", runner.binary, runner.stopped)
	}
	if got := h.read(filepath.Join(h.env.Layout.BinDir, binSensorHelper)); got != "defenseclaw-sensor-helper 1.0.0\n" {
		t.Fatalf("the previous helper was not restored: %q", got)
	}
	if !strings.Contains(strings.Join(r.Changes, "\n"), "the restored sensor helper loads its own again") {
		t.Fatalf("changes %v", r.Changes)
	}
}

// interruptedHelperUpgrade leaves the pending transaction of an upgrade that
// died after it put its own helper (2.0.0) in place, while the services ran
// on: the next lifecycle run rolls it back with the files first.
func interruptedHelperUpgrade(t *testing.T, h *testHost) string {
	t.Helper()
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	helper := filepath.Join(h.env.Layout.BinDir, binSensorHelper)
	snap, err := h.env.takeSnapshot("crash", []string{helper}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.savePending(&Pending{Action: ActionUpgrade, SnapshotDir: snap.Dir, Phase: "apply",
		PreviouslyActive: []string{unitGateway, unitSensorHelper}}); err != nil {
		t.Fatal(err)
	}
	staged := h.env.P(helper) + ".new"
	if err := os.WriteFile(staged, []byte("defenseclaw-sensor-helper 2.0.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, h.env.P(helper)); err != nil {
		t.Fatal(err)
	}
	if !h.services.isActive(unitSensorHelper) {
		t.Fatal("the helper must be running when the transaction is interrupted")
	}
	h.recordTetragonPolicies(recordedTetragonPolicies...)
	return helper
}

// The rollback of an interrupted transaction puts the files back while the
// services run, but the transaction's helper retires its Tetragon policies
// only once that helper is stopped: a running helper reads their removal as an
// operator's deletion and never loads them again. The previous helper then
// starts and loads its own.
func TestInterruptedTransactionRetiresTheTetragonPoliciesWithTheHelperStopped(t *testing.T) {
	h := newTestHost(t, "linux")
	helper := interruptedHelperUpgrade(t, h)
	runner := &tetragonHelperRunner{Runner: h.runner, h: h}
	h.env.Runner = runner
	r := h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if !hasWarning(r, codeRecovered) {
		t.Fatalf("expected recovery warning: %+v", r.Warnings)
	}
	if runner.binary != "defenseclaw-sensor-helper 2.0.0\n" || !runner.stopped {
		t.Fatalf("the cleanup must run with the transaction's helper once it is stopped: binary %q stopped %v", runner.binary, runner.stopped)
	}
	if got := h.read(helper); got != "defenseclaw-sensor-helper 1.0.0\n" {
		t.Fatalf("the previous helper was not restored: %q", got)
	}
	if !h.services.isActive(unitSensorHelper) {
		t.Fatal("the restored helper is not running")
	}
}

// When the files still cannot go back, the helper stopped for the cleanup is
// started again, so it manages its own policies as before the run.
func TestInterruptedTransactionThatCannotRestoreRestartsTheHelper(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	h := newTestHost(t, "linux")
	interruptedHelperUpgrade(t, h)
	runner := &tetragonHelperRunner{Runner: h.runner, h: h}
	h.env.Runner = runner
	bin := h.env.P(h.env.Layout.BinDir)
	if err := os.Chmod(bin, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bin, 0o755) })
	calls := len(h.services.calls)
	r := h.run(Options{Action: ActionEnsure})
	requireError(t, r, codeRollbackFailed)
	if !runner.stopped {
		t.Fatal("the cleanup ran while the helper was running")
	}
	got := strings.Join(h.services.calls[calls:], "\n")
	if !strings.Contains(got, "stop "+unitSensorHelper) || !strings.Contains(got, "start "+unitSensorHelper) || !h.services.isActive(unitSensorHelper) {
		t.Fatalf("the helper must be stopped for the cleanup and started again: %v", h.services.calls[calls:])
	}
	if strings.Contains(got, "stop "+unitGateway) {
		t.Fatalf("a restore that fails must leave the other services alone: %v", h.services.calls[calls:])
	}
}

// verify fails only on DefenseClaw-owned state: recorded policies with no
// helper running, and a policy of DefenseClaw's that did not load. The
// helper's other conditions are warnings.
func TestVerifyFailsOnOrphanedOrFailedKernelPolicies(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: tetragonTestConfig(t, h, "    mode: observe\n", true)}))
	now := time.Now().UTC()
	state := kernelpolicy.FileState{
		Version: 1, UpdatedAt: now, KernelPolicy: kernelpolicy.Digest(), Effective: "observe", InSync: true,
		Intent:    kernelpolicy.IntentStatus{Mode: kernelpolicy.ModeObserve, BurnIn: "168h"},
		Tetragon:  kernelpolicy.TetragonStatus{Reachable: true, Version: "v1.7.1"},
		Policies:  []kernelpolicy.PolicyStatus{{Name: recordedTetragonPolicies[1], Family: kernelpolicy.FamilyObserve, DesiredMode: kernelpolicy.PolicyMonitor, ObservedMode: kernelpolicy.LoadedMonitor, State: kernelpolicy.StateEnabled}},
		Overrides: map[kernelpolicy.Family]kernelpolicy.Override{kernelpolicy.FamilyControls: {Kind: kernelpolicy.OverrideMonitor, At: now}},
		Warnings:  []string{kernelpolicy.WarnForeignName + ":defenseclaw-foo", kernelpolicy.WarnReconcileFailed},
	}
	h.writeTetragonState(state)
	h.recordTetragonPolicies(recordedTetragonPolicies...)
	verify := h.run(Options{Action: ActionVerify})
	for _, code := range []string{kernelpolicy.WarnOperatorOverride + ":controls", kernelpolicy.WarnForeignName + ":defenseclaw-foo", kernelpolicy.WarnReconcileFailed} {
		if !hasWarning(verify, code) {
			t.Fatalf("verify lacks warning %s: %+v", code, verify.Warnings)
		}
	}
	if strings.Contains(messagesOf(verify.Errors, codeVerify), "kernel_") {
		t.Fatalf("a healthy helper's warnings must not fail verify: %+v", verify.Errors)
	}

	h.services.active[unitSensorHelper] = false
	verify = h.run(Options{Action: ActionVerify})
	if !strings.Contains(messagesOf(verify.Errors, codeVerify), codeKernelPolicyOrphaned+": the sensor helper is not running") {
		t.Fatalf("verify must fail on policies with no helper: %+v", verify.Errors)
	}
	h.services.active[unitSensorHelper] = true

	state.Policies[0].State, state.Policies[0].Error = kernelpolicy.StateLoadError, "selector rejected"
	h.writeTetragonState(state)
	verify = h.run(Options{Action: ActionVerify})
	if !strings.Contains(messagesOf(verify.Errors, codeVerify), kernelpolicy.WarnPolicyLoadError+":"+recordedTetragonPolicies[1]) {
		t.Fatalf("verify must fail on a policy that did not load: %+v", verify.Errors)
	}

	// Without Tetragon, consume reads nothing and says nothing.
	plain := newTestHost(t, "linux")
	requireOK(t, plain.run(Options{Action: ActionInstall, PayloadDir: plain.payload("1.0.0"), ConfigFile: tetragonTestConfig(t, plain, "", true)}))
	plain.writeTetragonState(kernelpolicy.FileState{Version: 1, UpdatedAt: now, KernelPolicy: kernelpolicy.Digest(), Effective: "consume",
		Intent: kernelpolicy.IntentStatus{Mode: kernelpolicy.ModeConsume}, Warnings: []string{kernelpolicy.WarnTetragonUnavailable}})
	if status := plain.run(Options{Action: ActionStatus}); hasWarning(status, kernelpolicy.WarnTetragonUnavailable) || !status.OK {
		t.Fatalf("consume on a host without Tetragon must not warn: %+v %+v", status.Warnings, status.Errors)
	}
}

// The gateway reports the helper's applied kernel_policy beside its policy
// generation's component; a difference means the helper did not restart.
func TestStatusWarnsWhenTheHelperRunsAnotherKernelPolicy(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	applied := "sha256:" + strings.Repeat("a", 12)
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		return 200, []byte(`{"api":{"state":"running"},"policy":{"effective_digest":"sha256:` + strings.Repeat("0", 64) + `","components":{"kernel_policy":"` +
			kernelpolicy.Digest() + `"},"kernel":{"kernel_policy":"` + applied + `"}},"inspection":{"local":"active","ai_defense":"disabled"}}`), nil
	}
	status := h.run(Options{Action: ActionStatus})
	if got := messagesOf(status.Warnings, codeKernelPolicyNotApplied); !strings.Contains(got, applied) || strings.Count(got, "\n") != 1 {
		t.Fatalf("warnings %+v", status.Warnings)
	}
	if applied, generation := gatewayKernelPolicy([]byte(`{"policy":{"effective_digest":"x"}}`)); applied != "" || generation != "" {
		t.Fatalf("a gateway without the fields: %q %q", applied, generation)
	}
}

func tetragonCLIHost(t *testing.T) *testHost {
	t.Helper()
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: tetragonTestConfig(t, h, "    mode: observe\n", true)}))
	old := tetragonLoginUID
	tetragonLoginUID = func() int { return 1234 }
	t.Cleanup(func() { tetragonLoginUID = old })
	return h
}

func TestTetragonPauseAndResume(t *testing.T) {
	h := tetragonCLIHost(t)
	ctx := context.Background()
	start := time.Now()
	rep := RunTetragon(ctx, h.env, TetragonOptions{Action: TetragonActionPause, For: time.Hour, Reason: "dccert maintenance window"})
	if !rep.OK || len(rep.Changes) != 1 || !strings.Contains(rep.Changes[0], "paused kernel enforcement until") {
		t.Fatalf("pause: %+v", rep)
	}
	var pause kernelpolicy.Pause
	if err := json.Unmarshal([]byte(h.read(filepath.Join(kernelpolicy.DefaultStateDir, "tetragon-pause"))), &pause); err != nil {
		t.Fatal(err)
	}
	if pause.SetByUID != 1234 || pause.Reason != "dccert maintenance window" || pause.UntilReboot ||
		pause.Until.Before(start.Add(time.Hour-time.Minute)) || pause.Until.After(time.Now().Add(time.Hour)) {
		t.Fatalf("pause file: %+v", pause)
	}
	if rep.Pause == nil {
		t.Fatal("the report does not show the pause it wrote")
	}

	reboot := RunTetragon(ctx, h.env, TetragonOptions{Action: TetragonActionPause, UntilReboot: true})
	if !reboot.OK || exists(h.env.P(filepath.Join(kernelpolicy.DefaultStateDir, "tetragon-pause"))) ||
		!exists(h.env.P(filepath.Join(kernelpolicy.DefaultRunDir, "tetragon-pause"))) {
		t.Fatalf("an until-reboot pause lives in the runtime directory only: %+v", reboot.Errors)
	}

	resume := RunTetragon(ctx, h.env, TetragonOptions{Action: TetragonActionResume})
	if !resume.OK || resume.Pause != nil || exists(h.env.P(filepath.Join(kernelpolicy.DefaultRunDir, "tetragon-pause"))) {
		t.Fatalf("resume: %+v", resume)
	}
	if again := RunTetragon(ctx, h.env, TetragonOptions{Action: TetragonActionResume}); !again.OK || again.Changes[0] != "no pause was in force" {
		t.Fatalf("resume without a pause: %+v", again.Changes)
	}

	for name, opts := range map[string]TetragonOptions{
		"both":       {Action: TetragonActionPause, For: time.Hour, UntilReboot: true},
		"too long":   {Action: TetragonActionPause, For: 8 * 24 * time.Hour},
		"negative":   {Action: TetragonActionPause, For: -time.Hour},
		"long note":  {Action: TetragonActionPause, Reason: strings.Repeat("x", 300)},
		"unknown op": {Action: "enforce-now"},
	} {
		if rep := RunTetragon(ctx, h.env, opts); rep.OK || rep.ExitCode != 2 {
			t.Fatalf("%s: exit %d %+v", name, rep.ExitCode, rep.Errors)
		}
	}
	h.env.Geteuid = func() int { return 1000 }
	if rep := RunTetragon(ctx, h.env, TetragonOptions{Action: TetragonActionStatus}); rep.OK || rep.Errors[0].Code != codeNotRoot {
		t.Fatalf("non-root: %+v", rep.Errors)
	}
	mac := newTestHost(t, "darwin")
	if rep := RunTetragon(ctx, mac.env, TetragonOptions{Action: TetragonActionStatus}); rep.ExitCode != 2 {
		t.Fatalf("macOS: %+v", rep)
	}
}

// fullTetragonState fills every field the status report shows.
func fullTetragonState(now time.Time) kernelpolicy.FileState {
	yes, no := true, false
	uid := 1001
	return kernelpolicy.FileState{
		Version: 1, UpdatedAt: now, HelperPID: 4242, KernelPolicy: kernelpolicy.Digest(), Effective: "observe", InSync: true,
		Intent:   kernelpolicy.IntentStatus{Mode: kernelpolicy.ModeObserve, BurnIn: "168h"},
		Tetragon: kernelpolicy.TetragonStatus{Reachable: true, Version: "v1.7.1", PID: 777, LSM: &yes, KeepSensorsOnExit: &no, SeenAt: now},
		Policies: []kernelpolicy.PolicyStatus{
			{Name: "defenseclaw-controls-0a1b2c3d", Family: kernelpolicy.FamilyControls, DesiredMode: kernelpolicy.PolicyMonitor, ObservedMode: kernelpolicy.LoadedMonitor, State: kernelpolicy.StateEnabled, ChangedAt: now},
			{Name: "defenseclaw-observe-11112222", Family: kernelpolicy.FamilyObserve, DesiredMode: kernelpolicy.PolicyMonitor, ObservedMode: kernelpolicy.LoadedMonitor, State: kernelpolicy.StateEnabled, ChangedAt: now},
		},
		Overrides: map[kernelpolicy.Family]kernelpolicy.Override{kernelpolicy.FamilyConnect: {Kind: kernelpolicy.OverrideDeleted, At: now}},
		UIDs: []kernelpolicy.UIDStatus{{UID: uid, User: "dcr-std1", Connectors: []string{"claudecode", "codex"}, State: "burn_in",
			Reason: "would-block hits", AnchoredRoots: 2, CoveredSeconds: 12 * 3600, NeededSeconds: 168 * 3600, WouldBlock: 1}},
		Roots:    kernelpolicy.RootsStatus{Anchored: 2, OverLimit: 1, Observed: []kernelpolicy.Observed{{UID: uid, Reason: kernelpolicy.ReasonHeuristicRoot, Identity: "langchain", Count: 1}}},
		Warnings: []string{kernelpolicy.WarnForeignName + ":defenseclaw-foo", kernelpolicy.WarnRootsOverLimit + ":1"},
	}
}

func compileTetragonStatusSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "tetragon_status.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	if err := compiler.AddResource("tetragon_status.schema.json", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("tetragon_status.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func validateTetragonReport(t *testing.T, schema *jsonschema.Schema, rep *TetragonReport) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteTetragonReport(&buf, rep, true); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("report does not match the schema: %v\n%s", err, buf.String())
	}
	return value
}

// The --json output follows the pinned schema, empty or full, and the text
// view shows what spec 10.2 lists.
func TestTetragonStatusFollowsTheSchema(t *testing.T) {
	schema := compileTetragonStatusSchema(t)
	h := tetragonCLIHost(t)
	ctx := context.Background()
	empty := RunTetragon(ctx, h.env, TetragonOptions{Action: TetragonActionStatus})
	if !empty.OK {
		t.Fatalf("status on a host the helper has not published to: %+v", empty.Errors)
	}
	validateTetragonReport(t, schema, empty)

	now := time.Now().UTC().Truncate(time.Second)
	h.writeTetragonState(fullTetragonState(now))
	h.recordTetragonPolicies(recordedTetragonPolicies...)
	burn := `{"version":1,"kernel_policy":"` + kernelpolicy.Digest() + `","uids":{"1001":{"connectors":["claudecode","codex"],"connectors_digest":"d","covered_seconds":43200,` +
		`"window_start":"` + now.Format(time.RFC3339) + `","would_block":{"kernel.ssh_private_key_read":{"count":1,"first":"` + now.Format(time.RFC3339) + `","last":"` + now.Format(time.RFC3339) +
		`","paths":[{"value":"/home/dcr-std1/.ssh/id_ed25519","count":1}],"binaries":[{"value":"/usr/bin/cat","count":1}]}}}}}`
	writeHostFile(t, h, filepath.Join(kernelpolicy.DefaultStateDir, "burnin.json"), burn)
	writeHostFile(t, h, tetragonInfoPath, `{"server_address":"unix:///var/run/tetragon/tetragon.sock","pid":777}`)
	writeHostFile(t, h, "/var/run/tetragon/tetragon.sock", "")
	h.owners[h.env.P("/var/run/tetragon/tetragon.sock")] = [2]int{0, 0}
	h.owners[h.env.P("/var/run/tetragon")] = [2]int{0, 0}
	// Written as this (non-root) user, the pause file is untrusted: it still
	// counts as a pause, and the report says why it is not trusted.
	if rep := RunTetragon(ctx, h.env, TetragonOptions{Action: TetragonActionPause, For: 2 * time.Hour, Reason: "dccert"}); !rep.OK {
		t.Fatalf("pause: %+v", rep.Errors)
	}
	full := RunTetragon(ctx, h.env, TetragonOptions{Action: TetragonActionStatus})
	value := validateTetragonReport(t, schema, full)
	for _, key := range []string{"pause", "tetragon", "users", "policies", "overrides", "foreign", "roots"} {
		if value[key] == nil {
			t.Fatalf("full report lacks %s", key)
		}
	}
	if full.Tetragon.Socket != "trusted (root-owned unix socket)" || !full.Tetragon.Installed || full.Tetragon.Version != "v1.7.1" {
		t.Fatalf("tetragon view %+v", full.Tetragon)
	}
	if len(full.Users) != 1 || len(full.Users[0].WouldBlock) != 1 || full.Users[0].CoveredHours != 12 || full.Users[0].NeededHours != 168 ||
		full.Users[0].WouldBlock[0].Paths[0].Value != "/home/dcr-std1/.ssh/id_ed25519" {
		t.Fatalf("users %+v", full.Users)
	}
	if !reflect.DeepEqual(full.Foreign, []string{"defenseclaw-foo"}) || !reflect.DeepEqual(full.Recorded, recordedTetragonPolicies) || len(full.Orphaned) != 0 {
		t.Fatalf("names: foreign %v recorded %v orphaned %v", full.Foreign, full.Recorded, full.Orphaned)
	}

	var text bytes.Buffer
	if err := WriteTetragonReport(&text, full, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Tetragon:       v1.7.1, pid 777, reachable, keep-sensors-on-exit false, BPF LSM true",
		"API socket:     trusted (root-owned unix socket) at unix:///var/run/tetragon/tetragon.sock",
		"Kernel policy:  " + kernelpolicy.Digest() + " (approve with `enforce_ack: " + kernelpolicy.Digest() + "`)",
		"Pause:          in force (untrusted pause file: ",
		"Override:       connect deleted",
		"defenseclaw-controls-0a1b2c3d", "dcr-std1 (1001)", "12.0h of 168.0h", "ssh_private_key_read 1 /home/dcr-std1/.ssh/id_ed25519 by /usr/bin/cat",
		"Observed, not enforced: 1 session(s)", "heuristic_root",
		kernelpolicy.WarnOperatorOverride + ":connect",
	} {
		if !strings.Contains(text.String(), want) {
			t.Fatalf("text view lacks %q:\n%s", want, text.String())
		}
	}

	// A trusted pause, as root writes it, shows who set it and why.
	state := kernelpolicy.State{FileState: fullTetragonState(now)}
	state.Pause = &kernelpolicy.PauseState{Pause: &kernelpolicy.Pause{Until: now.Add(time.Hour), SetByUID: 1234, SetAt: now, Reason: "dccert maintenance"}}
	trusted := &TetragonReport{SchemaVersion: TetragonStatusSchemaVersion, Action: TetragonActionStatus, OK: true, KernelPolicy: kernelpolicy.Digest(),
		ApproveWith: "enforce_ack: " + kernelpolicy.Digest(), Policies: []TetragonPolicy{}, Users: []TetragonUser{}, Overrides: []TetragonOverride{},
		Recorded: []string{}, Orphaned: []string{}, Foreign: []string{}, Roots: TetragonRoots{ObservedOnly: []TetragonObserved{}}}
	trusted.fill(h.env, tetragonIntent{Written: true, Configured: "observe", Mode: "observe", BurnIn: "168h"}, true, state, true, h.env.tetragonHost())
	trusted.Warnings, trusted.Errors = nil, nil
	if err := WriteTetragonReport(&text, trusted, false); err != nil {
		t.Fatal(err)
	}
	if want := "Pause:          until " + now.Add(time.Hour).Format(time.RFC3339) + ", set by uid 1234 at " + now.Format(time.RFC3339) + ": dccert maintenance"; !strings.Contains(text.String(), want) {
		t.Fatalf("text view lacks %q:\n%s", want, text.String())
	}
	trusted.Warnings, trusted.Errors = []enterprisestatus.Message{}, []enterprisestatus.Message{}
	validateTetragonReport(t, schema, trusted)

	h.services.active[unitSensorHelper] = false
	orphaned := RunTetragon(ctx, h.env, TetragonOptions{Action: TetragonActionStatus})
	validateTetragonReport(t, schema, orphaned)
	if orphaned.OK || orphaned.ExitCode != 1 || !reflect.DeepEqual(orphaned.Orphaned, recordedTetragonPolicies) {
		t.Fatalf("orphaned: exit %d %v %+v", orphaned.ExitCode, orphaned.Orphaned, orphaned.Errors)
	}
}

// Every field the report renders is described by the schema, so the schema
// cannot fall behind the type.
func TestTetragonStatusSchemaDescribesEveryField(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "tetragon_status.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	properties := func(node map[string]any) []string {
		var out []string
		if props, ok := node["properties"].(map[string]any); ok {
			for key := range props {
				out = append(out, key)
			}
		}
		sort.Strings(out)
		return out
	}
	fields := func(value any) []string {
		var out []string
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumField(); i++ {
			name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}
	props := schema["properties"].(map[string]any)
	defs := schema["$defs"].(map[string]any)
	item := func(node any) map[string]any {
		m := node.(map[string]any)
		if ref, ok := m["$ref"].(string); ok {
			m = defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
		}
		if items, ok := m["items"].(map[string]any); ok {
			return items
		}
		return m
	}
	for _, tc := range []struct {
		node  map[string]any
		value any
	}{
		{schema, TetragonReport{}},
		{props["intent"].(map[string]any), TetragonIntentView{}},
		{props["helper"].(map[string]any), TetragonHelperView{}},
		{props["tetragon"].(map[string]any), TetragonAgentView{}},
		{item(props["policies"]), TetragonPolicy{}},
		{item(props["users"]), TetragonUser{}},
		{props["roots"].(map[string]any), TetragonRoots{}},
		{item(props["roots"].(map[string]any)["properties"].(map[string]any)["observed_only"]), TetragonObserved{}},
		{props["pause"].(map[string]any), TetragonPauseView{}},
		{item(props["overrides"]), TetragonOverride{}},
		{item(defs["hits"]), TetragonHits{}},
		{item(defs["counts"]), TetragonCount{}},
	} {
		if got, want := properties(tc.node), fields(tc.value); !reflect.DeepEqual(got, want) {
			t.Fatalf("%T: schema properties %v, fields %v", tc.value, got, want)
		}
	}
}

// The findings table: what is a warning, what is a problem, and what is
// silent.
func TestTetragonFindings(t *testing.T) {
	now := time.Now().UTC()
	observe := tetragonIntent{Written: true, Configured: "observe", Mode: "observe", BurnIn: "168h"}
	installed := tetragonHost{Installed: true, Address: "unix:///var/run/tetragon/tetragon.sock", Verdict: "trusted (root-owned unix socket)"}
	running := kernelpolicy.State{FileState: kernelpolicy.FileState{UpdatedAt: now, KernelPolicy: kernelpolicy.Digest(), InSync: true,
		Intent: kernelpolicy.IntentStatus{Mode: kernelpolicy.ModeObserve}, Tetragon: kernelpolicy.TetragonStatus{Reachable: true}}}
	codes := func(findings []tetragonFinding) (warnings, problems []string) {
		for _, f := range findings {
			if f.Problem {
				problems = append(problems, f.Code)
			} else {
				warnings = append(warnings, f.Code)
			}
		}
		return warnings, problems
	}

	if w, p := codes(tetragonFindings("linux", observe, true, running, true, installed)); len(w)+len(p) != 0 {
		t.Fatalf("a healthy observe host: %v %v", w, p)
	}
	stale := running
	stale.KernelPolicy = "sha256:ffffffffffff"
	if w, _ := codes(tetragonFindings("linux", observe, true, stale, true, installed)); !reflect.DeepEqual(w, []string{codeKernelPolicyNotApplied}) {
		t.Fatalf("a helper on another control set: %v", w)
	}
	moved := running
	moved.Intent.Mode = kernelpolicy.ModeConsume
	if w, _ := codes(tetragonFindings("linux", observe, true, moved, true, installed)); !reflect.DeepEqual(w, []string{codeKernelPolicyNotApplied}) {
		t.Fatalf("a helper still on the previous drop-in: %v", w)
	}
	behind := running
	behind.InSync = false
	if w, _ := codes(tetragonFindings("linux", observe, true, behind, true, installed)); !reflect.DeepEqual(w, []string{codeKernelPolicyNotApplied}) {
		t.Fatalf("a pass that did not apply the plan: %v", w)
	}
	behind.Tetragon.Reachable = false
	if w, _ := codes(tetragonFindings("linux", observe, true, behind, true, installed)); len(w) != 0 {
		t.Fatalf("an unreachable Tetragon is reported by the helper's own warning: %v", w)
	}
	paused := running
	paused.Pause = &kernelpolicy.PauseState{Pause: &kernelpolicy.Pause{Until: now.Add(time.Hour), SetByUID: 1000, SetAt: now, Reason: "dccert"}}
	if w, _ := codes(tetragonFindings("linux", observe, true, paused, true, installed)); !reflect.DeepEqual(w, []string{kernelpolicy.WarnEnforcePaused}) {
		t.Fatalf("paused: %v", w)
	}
	untrusted := running
	untrusted.Pause = &kernelpolicy.PauseState{Invalid: "tetragon-pause: not a root-owned regular file"}
	if w, _ := codes(tetragonFindings("linux", observe, true, untrusted, true, installed)); !reflect.DeepEqual(w, []string{kernelpolicy.WarnPauseInvalid}) {
		t.Fatalf("an untrusted pause: %v", w)
	}

	down := running
	down.Tetragon = kernelpolicy.TetragonStatus{Reason: "dial unix /var/run/tetragon/tetragon.sock: connect: no such file"}
	down.Warnings = []string{kernelpolicy.WarnTetragonUnavailable}
	if w, p := codes(tetragonFindings("linux", observe, true, down, true, tetragonHost{})); !reflect.DeepEqual(w, []string{kernelpolicy.WarnTetragonUnavailable}) || len(p) != 0 {
		t.Fatalf("an outage in observe is a warning only: %v %v", w, p)
	}
	consume := tetragonIntent{Configured: "consume", Mode: "consume", BurnIn: "168h"}
	down.Intent.Mode = kernelpolicy.ModeConsume
	if w, _ := codes(tetragonFindings("linux", consume, true, down, true, tetragonHost{})); len(w) != 0 {
		t.Fatalf("consume without Tetragon installed: %v", w)
	}
	if w, _ := codes(tetragonFindings("linux", consume, true, down, true, installed)); !reflect.DeepEqual(w, []string{kernelpolicy.WarnTetragonUnavailable}) {
		t.Fatalf("consume with Tetragon installed but unreachable: %v", w)
	}

	// A refused endpoint is named by its own code, in every mode.
	refused := down
	refused.Tetragon.Reason = "tetragon_tcp_api: the info file names localhost:54321"
	tcp := tetragonHost{Installed: true, Address: "localhost:54321", TCP: true}
	if w, _ := codes(tetragonFindings("linux", consume, true, refused, true, tcp)); !reflect.DeepEqual(w, []string{codeTetragonTCPAPI}) {
		t.Fatalf("a TCP API: %v", w)
	}
	if w, _ := codes(tetragonFindings("linux", consume, true, kernelpolicy.State{}, true, tcp)); !reflect.DeepEqual(w, []string{codeTetragonTCPAPI}) {
		t.Fatalf("a TCP API the helper never reported: %v", w)
	}
	refused.Tetragon.Reason = "tetragon_untrusted_endpoint: /var/run/tetragon is world-writable"
	if w, _ := codes(tetragonFindings("linux", consume, true, refused, true, installed)); !reflect.DeepEqual(w, []string{"tetragon_untrusted_endpoint"}) {
		t.Fatalf("an untrusted endpoint: %v", w)
	}

	left := running
	left.Loaded = recordedTetragonPolicies
	if _, p := codes(tetragonFindings("linux", observe, true, left, true, installed)); len(p) != 0 {
		t.Fatalf("recorded policies with the helper running are its own: %v", p)
	}
	if _, p := codes(tetragonFindings("linux", observe, true, left, false, installed)); !reflect.DeepEqual(p, []string{codeKernelPolicyOrphaned}) {
		t.Fatalf("recorded policies with no helper: %v", p)
	}
	retired := left
	retired.Intent.Mode = kernelpolicy.ModeConsume
	if _, p := codes(tetragonFindings("linux", consume, true, retired, true, installed)); !reflect.DeepEqual(p, []string{codeKernelPolicyOrphaned}) {
		t.Fatalf("recorded policies after the consume retire step: %v", p)
	}
	retired.Tetragon.Reachable = false
	if _, p := codes(tetragonFindings("linux", consume, true, retired, true, installed)); len(p) != 0 {
		t.Fatalf("an unreachable Tetragon is never a problem: %v", p)
	}

	if w, _ := codes(tetragonFindings("darwin", tetragonIntent{Reason: config.TetragonReasonNotApplicable}, true, kernelpolicy.State{}, false, tetragonHost{})); !reflect.DeepEqual(w, []string{config.TetragonReasonNotApplicable}) {
		t.Fatalf("macOS: %v", w)
	}
}

// The packaged helper unit orders itself after Tetragon without pulling it
// in, keeps its state directory and its runtime directory across stops (the
// until-reboot pause), and gains no capability.
func TestSensorHelperUnitKeepsTetragonState(t *testing.T) {
	data, err := systemdunits.ReadFile(unitSensorHelper)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	for _, want := range []string{"After=tetragon.service", "StateDirectory=defenseclaw-sensor", "StateDirectoryMode=0700", "RuntimeDirectoryPreserve=yes",
		"CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_CHOWN CAP_FOWNER"} {
		if !contains(lines, want) {
			t.Fatalf("the sensor helper unit lacks %q", want)
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "Wants=") || strings.HasPrefix(line, "Requires=") || strings.HasPrefix(line, "BindsTo=") {
			if strings.Contains(line, "tetragon") {
				t.Fatalf("the unit must not pull Tetragon in: %q", line)
			}
		}
	}
}

func TestCleanupRemovedParsesOnlyDefenseClawNames(t *testing.T) {
	out := cleanupRemoved([]byte("removed defenseclaw-observe-11112222\nalready gone defenseclaw-controls-0a1b2c3d\nremoved defenseclaw-foo\nremoved defenseclaw-connect-aaaaaaaa\n"))
	if !reflect.DeepEqual(out, []string{"defenseclaw-connect-aaaaaaaa", "defenseclaw-observe-11112222"}) {
		t.Fatalf("removed %v", out)
	}
}
