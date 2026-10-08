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
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// machinePolicyAnchorsLine is the drop-in line of the test config's two
// connectors: both are on vendor machine policy on Linux and, with the
// default enrollment.unenrolled_users, have no targets.yaml rows.
const machinePolicyAnchorsLine = kernelpolicy.EnvMachinePolicyConnectors + "=claudecode,codex"

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
	if got, want := h.read(tetragonDropinPath), expectedTetragonDropin("observe", "48h", "", "", machinePolicyAnchorsLine); got != want {
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
	if record, _ := h.env.loadDeployment(); record == nil {
		t.Fatal("no deployment record")
	}
	if r := h.run(Options{Action: ActionEnsure, ConfigFile: tetragonTestConfig(t, h, "    mode: observe\n    burn_in: 72h\n", true)}); !strings.Contains(strings.Join(r.Changes, "\n"), "the sensor helper restarted into enterprise.tetragon mode observe") {
		t.Fatalf("ensure does not say the helper restarted into the new mode: %v", r.Changes)
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
	if r := h.run(Options{Action: ActionEnsure}); strings.Contains(strings.Join(r.Changes, "\n"), "restarted into enterprise.tetragon") {
		t.Fatalf("an unchanged drop-in names no helper restart: %v", r.Changes)
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
			dropin:   expectedTetragonDropin("enforce", "168h", digest, "claudecode", machinePolicyAnchorsLine),
			warnings: []string{kernelpolicy.WarnGuardrailObserve + ":codex"},
			absent:   []string{kernelpolicy.WarnEnforceAckMissing, kernelpolicy.WarnEnforceAckStale, kernelpolicy.WarnBurnInSkipped},
		},
		{
			name: "enforce without approval", block: "    mode: enforce\n    burn_in: 0\n", planeC: true,
			dropin:   expectedTetragonDropin("enforce", "0", "", "claudecode", machinePolicyAnchorsLine),
			warnings: []string{kernelpolicy.WarnEnforceAckMissing, kernelpolicy.WarnBurnInSkipped},
		},
		{
			name: "stale approval", block: "    mode: enforce\n    enforce_ack: sha256:000000000000\n", planeC: true,
			dropin:   expectedTetragonDropin("enforce", "168h", "sha256:000000000000", "claudecode", machinePolicyAnchorsLine),
			warnings: []string{kernelpolicy.WarnEnforceAckStale},
		},
		{
			name: "observe keeps an approval inert", block: "    mode: observe\n    enforce_ack: sha256:000000000000\n", planeC: true,
			dropin: expectedTetragonDropin("observe", "168h", "sha256:000000000000", "", machinePolicyAnchorsLine),
			absent: []string{kernelpolicy.WarnEnforceAckStale, kernelpolicy.WarnGuardrailObserve + ":codex"},
		},
		{
			// A ring upgrade approves the old and the new build at once: the
			// list reaches the helper as a comma list and approves this build.
			name: "approval list", block: "    mode: enforce\n    enforce_ack: [sha256:000000000000, " + digest + "]\n", planeC: true,
			dropin: expectedTetragonDropin("enforce", "168h", "sha256:000000000000,"+digest, "claudecode", machinePolicyAnchorsLine),
			absent: []string{kernelpolicy.WarnEnforceAckMissing, kernelpolicy.WarnEnforceAckStale},
		},
		{
			name: "approval list without this build", block: "    mode: enforce\n    enforce_ack:\n      - sha256:000000000000\n      - sha256:111111111111\n", planeC: true,
			dropin:   expectedTetragonDropin("enforce", "168h", "sha256:000000000000,sha256:111111111111", "claudecode", machinePolicyAnchorsLine),
			warnings: []string{kernelpolicy.WarnEnforceAckStale},
		},
		{
			// With unenrolled_users: deny the enumerator writes per-user rows
			// for the machine-policy connectors; targets.yaml is the whole
			// enrollment and the helper adds nothing.
			name: "unenrolled users denied", block: "    mode: observe\n  enrollment:\n    unenrolled_users: deny\n", planeC: true,
			dropin: expectedTetragonDropin("observe", "168h", "", ""),
		},
		{
			// The administrator publishes targets.yaml (enrollment.mode
			// manifest): its rows are the whole enrollment.
			name: "manifest enrollment", block: "    mode: observe\n  enrollment:\n    mode: manifest\n", planeC: true,
			dropin: expectedTetragonDropin("observe", "168h", "", ""),
		},
		{
			// A connector whose machine policy is left alone has no
			// DefenseClaw route, so no anchor either.
			name: "machine policy ownership off", block: "    mode: observe\n  machine_policy:\n    connectors:\n      codex:\n        ownership: off\n", planeC: true,
			dropin: expectedTetragonDropin("observe", "168h", "", "", kernelpolicy.EnvMachinePolicyConnectors+"=claudecode"),
		},
		{
			// customer_events alone is a written block; its variable appears
			// only when it is not the default.
			name: "customer events off", block: "    customer_events: off\n", planeC: true,
			dropin: expectedTetragonDropin("consume", "168h", "", "", kernelpolicy.EnvCustomerEvents+"=off"),
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
	stubTetragonAccounts(t)
	return h
}

// GAP-0046: a pause or resume that wrote its file succeeds whatever else
// the host reports (here a recorded policy with no helper running, which
// status fails on), and prints the change, not the whole status: the fleet
// emergency-pause play marked paused hosts failed.
func TestTetragonPauseSucceedsWhateverTheHostReports(t *testing.T) {
	h := tetragonCLIHost(t)
	ctx := context.Background()
	h.recordTetragonPolicies(recordedTetragonPolicies...)
	h.services.active[unitSensorHelper] = false
	if status := RunTetragon(ctx, h.env, TetragonOptions{Action: TetragonActionStatus}); status.OK {
		t.Fatalf("test setup: status found no problem: %+v", status.Errors)
	}
	for _, action := range []string{TetragonActionPause, TetragonActionResume} {
		rep := RunTetragon(ctx, h.env, TetragonOptions{Action: action, For: time.Hour, Reason: "dccert"})
		if !rep.OK || rep.ExitCode != 0 || len(rep.Errors) != 0 || len(rep.Warnings) == 0 {
			t.Fatalf("%s: ok %v exit %d errors %+v warnings %+v", action, rep.OK, rep.ExitCode, rep.Errors, rep.Warnings)
		}
		var out strings.Builder
		if err := WriteTetragonReport(&out, rep, false); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "✓ ") || !strings.Contains(lines[1], "tetragon status") {
			t.Fatalf("%s printed:\n%s", action, out.String())
		}
	}
}

func TestTetragonPauseAndResume(t *testing.T) {
	h := tetragonCLIHost(t)
	ctx := context.Background()
	start := time.Now()
	rep := RunTetragon(ctx, h.env, TetragonOptions{Action: TetragonActionPause, For: time.Hour, Reason: "dccert maintenance window"})
	if !rep.OK || len(rep.Changes) != 1 || !strings.Contains(rep.Changes[0], "paused kernel enforcement for every user on this host until") {
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
		"  Tetragon:        v1.7.1, pid 777, reachable, keep-sensors-on-exit false, BPF LSM true\n",
		"  API socket:      trusted (root-owned unix socket) at unix:///var/run/tetragon/tetragon.sock\n",
		"  Kernel controls: " + kernelpolicy.Digest() + ", in monitor mode; enforce_ack approves this digest\n",
		"  Pause:           in force for every user on this host (untrusted pause file: ",
		"  Override:        connect deleted by an operator at ",
		"defenseclaw-controls-0a1b2c3d", "dcr-std1 (1001)", "reset by a hit", "12.0h of 168h (7%)",
		"      dcr-std1 (1001): would block ssh_private_key_read 1x, last ", "        ~/.ssh/id_ed25519 by /usr/bin/cat\n",
		"Observed, not enforced: 1 session(s)", "    dcr-std1 (uid 1001): 1, looks like an agent by name only (heuristic_root) (langchain)",
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
	if want := "  Pause:           until " + now.Add(time.Hour).Format(time.RFC3339) + ", set by uid 1234 at " + now.Format(time.RFC3339) + ": dccert maintenance (every user on this host)\n"; !strings.Contains(text.String(), want) {
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
			if !typ.Field(i).IsExported() {
				continue // text-view state, never marshalled
			}
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
		{item(props["customer_policies"]), TetragonCustomerPolicy{}},
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

	if w, p := codes(findingsOf("linux", observe, true, running, true, installed)); len(w)+len(p) != 0 {
		t.Fatalf("a healthy observe host: %v %v", w, p)
	}
	stale := running
	stale.KernelPolicy = "sha256:ffffffffffff"
	if w, _ := codes(findingsOf("linux", observe, true, stale, true, installed)); !reflect.DeepEqual(w, []string{codeKernelPolicyNotApplied}) {
		t.Fatalf("a helper on another control set: %v", w)
	}
	moved := running
	moved.Intent.Mode = kernelpolicy.ModeConsume
	if w, _ := codes(findingsOf("linux", observe, true, moved, true, installed)); !reflect.DeepEqual(w, []string{codeKernelPolicyNotApplied}) {
		t.Fatalf("a helper still on the previous drop-in: %v", w)
	}
	behind := running
	behind.InSync = false
	if w, _ := codes(findingsOf("linux", observe, true, behind, true, installed)); !reflect.DeepEqual(w, []string{codeKernelPolicyNotApplied}) {
		t.Fatalf("a pass that did not apply the plan: %v", w)
	}
	behind.Tetragon.Reachable = false
	if w, _ := codes(findingsOf("linux", observe, true, behind, true, installed)); len(w) != 0 {
		t.Fatalf("an unreachable Tetragon is reported by the helper's own warning: %v", w)
	}
	paused := running
	paused.Pause = &kernelpolicy.PauseState{Pause: &kernelpolicy.Pause{Until: now.Add(time.Hour), SetByUID: 1000, SetAt: now, Reason: "dccert"}}
	if w, _ := codes(findingsOf("linux", observe, true, paused, true, installed)); !reflect.DeepEqual(w, []string{kernelpolicy.WarnEnforcePaused}) {
		t.Fatalf("paused: %v", w)
	}
	untrusted := running
	untrusted.Pause = &kernelpolicy.PauseState{Invalid: "tetragon-pause: not a root-owned regular file"}
	if w, _ := codes(findingsOf("linux", observe, true, untrusted, true, installed)); !reflect.DeepEqual(w, []string{kernelpolicy.WarnPauseInvalid}) {
		t.Fatalf("an untrusted pause: %v", w)
	}

	down := running
	down.Tetragon = kernelpolicy.TetragonStatus{Reason: "dial unix /var/run/tetragon/tetragon.sock: connect: no such file"}
	down.Warnings = []string{kernelpolicy.WarnTetragonUnavailable}
	if w, p := codes(findingsOf("linux", observe, true, down, true, tetragonHost{})); !reflect.DeepEqual(w, []string{kernelpolicy.WarnTetragonUnavailable}) || len(p) != 0 {
		t.Fatalf("an outage in observe is a warning only: %v %v", w, p)
	}
	consume := tetragonIntent{Configured: "consume", Mode: "consume", BurnIn: "168h"}
	down.Intent.Mode = kernelpolicy.ModeConsume
	if w, _ := codes(findingsOf("linux", consume, true, down, true, tetragonHost{})); len(w) != 0 {
		t.Fatalf("consume without Tetragon installed: %v", w)
	}
	if w, _ := codes(findingsOf("linux", consume, true, down, true, installed)); !reflect.DeepEqual(w, []string{kernelpolicy.WarnTetragonUnavailable}) {
		t.Fatalf("consume with Tetragon installed but unreachable: %v", w)
	}

	// A refused endpoint is named by its own code, in every mode.
	refused := down
	refused.Tetragon.Reason = "tetragon_tcp_api: the info file names localhost:54321"
	tcp := tetragonHost{Installed: true, Address: "localhost:54321", TCP: true}
	if w, _ := codes(findingsOf("linux", consume, true, refused, true, tcp)); !reflect.DeepEqual(w, []string{codeTetragonTCPAPI}) {
		t.Fatalf("a TCP API: %v", w)
	}
	if w, _ := codes(findingsOf("linux", consume, true, kernelpolicy.State{}, true, tcp)); !reflect.DeepEqual(w, []string{codeTetragonTCPAPI}) {
		t.Fatalf("a TCP API the helper never reported: %v", w)
	}
	refused.Tetragon.Reason = "tetragon_untrusted_endpoint: /var/run/tetragon is world-writable"
	if w, _ := codes(findingsOf("linux", consume, true, refused, true, installed)); !reflect.DeepEqual(w, []string{"tetragon_untrusted_endpoint"}) {
		t.Fatalf("an untrusted endpoint: %v", w)
	}

	left := running
	left.Loaded = recordedTetragonPolicies
	if _, p := codes(findingsOf("linux", observe, true, left, true, installed)); len(p) != 0 {
		t.Fatalf("recorded policies with the helper running are its own: %v", p)
	}
	if _, p := codes(findingsOf("linux", observe, true, left, false, installed)); !reflect.DeepEqual(p, []string{codeKernelPolicyOrphaned}) {
		t.Fatalf("recorded policies with no helper: %v", p)
	}
	retired := left
	retired.Intent.Mode = kernelpolicy.ModeConsume
	if _, p := codes(findingsOf("linux", consume, true, retired, true, installed)); !reflect.DeepEqual(p, []string{codeKernelPolicyOrphaned}) {
		t.Fatalf("recorded policies after the consume retire step: %v", p)
	}
	retired.Tetragon.Reachable = false
	if _, p := codes(findingsOf("linux", consume, true, retired, true, installed)); len(p) != 0 {
		t.Fatalf("an unreachable Tetragon is never a problem: %v", p)
	}

	if w, _ := codes(findingsOf("darwin", tetragonIntent{Reason: config.TetragonReasonNotApplicable}, true, kernelpolicy.State{}, false, tetragonHost{})); !reflect.DeepEqual(w, []string{config.TetragonReasonNotApplicable}) {
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
		"RuntimeDirectory=defenseclaw-sensor " + filepath.Base(kernelpolicy.DefaultRunDir),
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
	// GAP-0031: the helper's regular runtime files (the until-reboot pause,
	// the policy copies) never sit in the socket's directory. The helper
	// gives that directory to the gateway's group, and systemd 252 then
	// chowns it back recursively at the next start and fails on any regular
	// file in it, so the helper could not restart after observe or a pause.
	layout, err := managed.StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	socketDir := layout.SensorSocketDir
	dirs := kernelpolicy.DefaultDirs()
	for _, path := range []string{dirs.Run, dirs.RuntimePause(), dirs.PolicyCopies()} {
		if path == socketDir || strings.HasPrefix(path, socketDir+"/") {
			t.Fatalf("%s is inside the socket's runtime directory %s", path, socketDir)
		}
	}
}

func TestCleanupRemovedParsesOnlyDefenseClawNames(t *testing.T) {
	out := cleanupRemoved([]byte("removed defenseclaw-observe-11112222\nalready gone defenseclaw-controls-0a1b2c3d\nremoved defenseclaw-foo\nremoved defenseclaw-connect-aaaaaaaa\n"))
	if !reflect.DeepEqual(out, []string{"defenseclaw-connect-aaaaaaaa", "defenseclaw-observe-11112222"}) {
		t.Fatalf("removed %v", out)
	}
}

// statusHost is a host whose sensor helper published state at readinessNow
// with Tetragon v1.7.1 reachable over a trusted socket; block is
// enterprise.tetragon.
func statusHost(t *testing.T, block string, state kernelpolicy.FileState, extra map[string]any) *testHost {
	t.Helper()
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: tetragonTestConfig(t, h, block, true)}))
	stubTetragonAccounts(t)
	h.env.Now = func() time.Time { return readinessNow }
	writeHostFile(t, h, tetragonInfoPath, `{"server_address":"unix:///var/run/tetragon/tetragon.sock","pid":912}`)
	writeHostFile(t, h, "/var/run/tetragon/tetragon.sock", "")
	h.owners[h.env.P("/var/run/tetragon/tetragon.sock")] = [2]int{0, 0}
	h.owners[h.env.P("/var/run/tetragon")] = [2]int{0, 0}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for key, value := range extra {
		doc[key] = value
	}
	data, _ = json.Marshal(doc)
	writeHostFile(t, h, filepath.Join(kernelpolicy.DefaultStateDir, "tetragon-state.json"), string(data))
	return h
}

func publishedState(mode kernelpolicy.Mode) kernelpolicy.FileState {
	yes, no := true, false
	return kernelpolicy.FileState{Version: 1, UpdatedAt: readinessNow.Add(-30 * time.Second), KernelPolicy: kernelpolicy.Digest(),
		Effective: string(mode), InSync: true, Intent: kernelpolicy.IntentStatus{Mode: mode, BurnIn: "168h"},
		Tetragon: kernelpolicy.TetragonStatus{Reachable: true, Version: "v1.7.1", PID: 912, LSM: &yes, KeepSensorsOnExit: &no}}
}

// writeBurnIn writes burnin.json for the promotion fixture users.
func writeBurnIn(t *testing.T, h *testHost) {
	t.Helper()
	in := withUsers(readyInputs("observe"))
	data, err := json.Marshal(kernelpolicy.BurnInFile{Version: 1, KernelPolicy: kernelpolicy.Digest(), UIDs: in.State.BurnIn.UIDs})
	if err != nil {
		t.Fatal(err)
	}
	writeHostFile(t, h, filepath.Join(kernelpolicy.DefaultStateDir, "burnin.json"), string(data))
}

func statusText(t *testing.T, rep *TetragonReport) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteTetragonReport(&buf, rep, false); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func assertStatusColumns(t *testing.T, text string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if len([]rune(line)) > 100 && !strings.HasPrefix(trimmed, "sudo ") && !strings.HasPrefix(line, "  ! ") && !strings.HasPrefix(line, "  ✗ ") {
			t.Errorf("status line over 100 columns (%d): %q", len([]rune(line)), line)
		}
	}
}

// status in consume: no approve hint (nothing is loaded), and the Next:
// footer from the readiness engine.
func TestTetragonStatusTextInConsume(t *testing.T) {
	h := statusHost(t, "", publishedState(kernelpolicy.ModeConsume), nil)
	rep := RunTetragon(context.Background(), h.env, TetragonOptions{Action: TetragonActionStatus})
	if !rep.OK {
		t.Fatalf("status: %+v", rep.Errors)
	}
	got := statusText(t, rep)
	want := `Tetragon (managed Linux)
  Tetragon:        v1.7.1, pid 912, reachable, keep-sensors-on-exit false, BPF LSM true
  API socket:      trusted (root-owned unix socket) at unix:///var/run/tetragon/tetragon.sock
  Sensor helper:   running, state updated 2026-10-07T11:59:30Z
  Mode:            consume, burn-in 168h
  Kernel controls: not loaded (mode consume)
Next: this host is ready for observe. Check with:
  sudo ` + adminBinDir + `/defenseclaw-gateway enterprise linux tetragon verify --ready-for observe
`
	if got != want {
		t.Fatalf("text:\n%s\nwant:\n%s", got, want)
	}
}

// status in observe with a user reset by a hit: words for states, burn-in
// with percent and ETA ("measuring" before a day), hit details with a
// home-relative path, and the next step toward enforce.
func TestTetragonStatusTextInObserveWithAResetUser(t *testing.T) {
	state := publishedState(kernelpolicy.ModeObserve)
	state.UIDs = withUsers(readyInputs("observe")).State.UIDs
	h := statusHost(t, "    mode: observe\n", state, nil)
	writeBurnIn(t, h)
	rep := RunTetragon(context.Background(), h.env, TetragonOptions{Action: TetragonActionStatus})
	got := statusText(t, rep)
	for _, want := range []string{
		"  Kernel controls: " + kernelpolicy.Digest() + ", in monitor mode; enforce_ack approves this digest\n",
		"    USER             STATE              CONNECTORS  BURN-IN                       HITS\n",
		"    dcr-std1 (1001)  ready for enforce  claudecode  168.0h of 168h, ready         0\n",
		"    dcr-std2 (1002)  in burn-in         claudecode  40.5h of 168h (24%), ~9 days  0\n",
		"    dcr-std3 (1003)  reset by a hit     claudecode  0.0h of 168h (0%), measuring  1\n",
		"      dcr-std3 (1003): would block ssh_private_key_read 1x, last 2026-10-07T09:12:00Z\n        ~/.ssh/id_ed25519 by /usr/bin/python3.11\n",
		"Next: 1 of 3 users is ready; the next is ready in ~9 days at the current rate. Check with:\n" +
			"  sudo " + adminBinDir + "/defenseclaw-gateway enterprise linux tetragon verify --ready-for enforce\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("text lacks %q:\n%s", want, got)
		}
	}
	assertStatusColumns(t, got)

	// --user narrows every list to one user, by name or uid; JSON keeps its shape.
	schema := compileTetragonStatusSchema(t)
	for _, who := range []string{"dcr-std3", "1003"} {
		one := RunTetragon(context.Background(), h.env, TetragonOptions{Action: TetragonActionStatus, User: who})
		validateTetragonReport(t, schema, one)
		if !one.OK || len(one.Users) != 1 || one.Users[0].UID != 1003 {
			t.Fatalf("--user %s: %+v %+v", who, one.Users, one.Errors)
		}
		if text := statusText(t, one); strings.Contains(text, "dcr-std1") || !strings.Contains(text, "reset by a hit") {
			t.Fatalf("--user %s text:\n%s", who, text)
		}
	}
	none := RunTetragon(context.Background(), h.env, TetragonOptions{Action: TetragonActionStatus, User: "nobody"})
	if none.OK || none.ExitCode != 2 || !strings.Contains(none.Errors[0].Message, "enrolled: dcr-std1, dcr-std2, dcr-std3") {
		t.Fatalf("--user nobody: %+v", none)
	}
}

// A user whose connectors are all in observe mode is never enforced, so
// observe does not call it ready for enforce whatever its burn-in says, and
// the Next: footer does not count it.
func TestTetragonStatusTextNamesMonitorOnlyUsers(t *testing.T) {
	state := publishedState(kernelpolicy.ModeObserve)
	state.UIDs = withUsers(readyInputs("observe")).State.UIDs
	state.UIDs[0].Connectors = []string{"codex"} // dcr-std1 finished burn-in, but runs only Codex (observe mode)
	state.UIDs[0].MachinePolicy = []string{"codex"}
	h := statusHost(t, "    mode: observe\n", state, nil)
	writeBurnIn(t, h)
	rep := RunTetragon(context.Background(), h.env, TetragonOptions{Action: TetragonActionStatus})
	got := statusText(t, rep)
	for _, want := range []string{
		"    dcr-std1 (1001)  monitor only    codex*      168.0h of 168h                0\n",
		"    * through vendor machine policy: an eligible account without a targets.yaml row\n",
		"      dcr-std1 (1001): monitor only: connector in observe mode\n",
		"Next: 0 of 3 users are ready; the next is ready in ~9 days at the current rate. Check with:\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("text lacks %q:\n%s", want, got)
		}
	}
	if !reflect.DeepEqual(rep.Users[0].MachinePolicy, []string{"codex"}) || !reflect.DeepEqual(rep.Users[1].MachinePolicy, []string{}) {
		t.Fatalf("machine_policy = %v / %v", rep.Users[0].MachinePolicy, rep.Users[1].MachinePolicy)
	}
	assertStatusColumns(t, got)
}

func TestConnectorsWordsMarkMachinePolicy(t *testing.T) {
	for _, tc := range []struct {
		user TetragonUser
		want string
	}{
		{TetragonUser{}, "-"},
		{TetragonUser{Connectors: []string{"amp", "opencode"}}, "amp,opencode"},
		{TetragonUser{Connectors: []string{"claudecode", "codex"}, MachinePolicy: []string{"claudecode", "codex"}}, "claudecode*,codex*"},
		{TetragonUser{Connectors: []string{"claudecode", "opencode"}, MachinePolicy: []string{"claudecode"}}, "claudecode*,opencode"},
	} {
		if got := connectorsWords(tc.user); got != tc.want {
			t.Errorf("connectorsWords(%+v) = %q, want %q", tc.user, got, tc.want)
		}
	}
}

// status in enforce with a stale approval: the controls line says the
// digest is not approved, and the next step is the approval.
func TestTetragonStatusTextInEnforceWithAStaleApproval(t *testing.T) {
	state := publishedState(kernelpolicy.ModeEnforce)
	state.Effective = "observe"
	state.UIDs = withUsers(readyInputs("observe")).State.UIDs
	h := statusHost(t, "    mode: enforce\n    enforce_ack: sha256:000000000000\n", state, nil)
	writeBurnIn(t, h)
	rep := RunTetragon(context.Background(), h.env, TetragonOptions{Action: TetragonActionStatus})
	got := statusText(t, rep)
	for _, want := range []string{
		"  Mode:            enforce, running as observe, burn-in 168h\n",
		"  Kernel controls: " + kernelpolicy.Digest() + ", enforce_ack is for another build (sha256:000000000000)\n",
		"  ! " + kernelpolicy.WarnEnforceAckStale + ": enforce_ack sha256:000000000000 does not include this build's " + kernelpolicy.Digest(),
		"or to `enterprise.tetragon.enforce_ack: [sha256:000000000000, " + kernelpolicy.Digest() + "]` while the ring upgrades",
		"Next: approve this build's kernel controls (enforce_ack). See:\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("text lacks %q:\n%s", want, got)
		}
	}
	assertStatusColumns(t, got)
}

// A paused host says the pause covers every user, and status still reads.
func TestTetragonStatusTextWhenPaused(t *testing.T) {
	h := statusHost(t, "    mode: enforce\n    enforce_ack: "+kernelpolicy.Digest()+"\n", publishedState(kernelpolicy.ModeEnforce), nil)
	if rep := RunTetragon(context.Background(), h.env, TetragonOptions{Action: TetragonActionPause, For: time.Hour, Reason: "dccert"}); !rep.OK ||
		!strings.Contains(rep.Changes[0], "for every user on this host") {
		t.Fatalf("pause: %+v", rep)
	}
	rep := RunTetragon(context.Background(), h.env, TetragonOptions{Action: TetragonActionStatus})
	got := statusText(t, rep)
	for _, want := range []string{
		"  Kernel controls: " + kernelpolicy.Digest() + ", approved\n",
		"  Pause:           in force for every user on this host (untrusted pause file: ",
		"(kernel enforcement stays paused for every user on this host); remove it with `sudo " + adminBinDir + "/defenseclaw-gateway enterprise linux tetragon resume`",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("text lacks %q:\n%s", want, got)
		}
	}
}

// Your own Tetragon policies: listed under their own heading with
// DefenseClaw's promise, counted from the helper's state, never touched.
func TestTetragonStatusListsYourPolicies(t *testing.T) {
	extra := map[string]any{
		"customer_policies": []map[string]any{
			{"name": "10-file-sensitive", "listed": true, "mode": "enforce", "state": "enabled", "seen": 120, "forwarded": 12, "dropped": 0,
				"blocked": 2, "actions": map[string]any{"post": 118, "override": 2, "signal": 3}, "last_event_at": "2026-10-07T11:58:00Z"},
			{"name": "20-net-connect", "listed": true, "mode": "monitor", "state": "enabled", "seen": 40, "forwarded": 3, "dropped": 9,
				"capped_last_hour": 7, "actions": map[string]any{"post": 40, "monitor_override": 5}},
			// Tetragon no longer lists it; the helper keeps it for the events it had.
			{"name": "30-removed", "listed": false, "seen": 5, "forwarded": 1, "dropped": 0},
		},
	}
	state := publishedState(kernelpolicy.ModeConsume)
	state.Warnings = []string{codeCustomerEventsCapped + ":20-net-connect"}
	h := statusHost(t, "", state, extra)
	writeHostFile(t, h, tetragonConfDir+"/health-server-address", ":6789\n")
	rep := RunTetragon(context.Background(), h.env, TetragonOptions{Action: TetragonActionStatus})
	validateTetragonReport(t, compileTetragonStatusSchema(t), rep)
	if len(rep.CustomerPolicies) != 3 || rep.CustomerPolicies[0].Blocked != 2 || rep.CustomerPolicies[1].Blocked != 0 || rep.CustomerPolicies[1].Dropped != 9 ||
		rep.CustomerPolicies[2].State != "not listed" {
		t.Fatalf("customer policies %+v", rep.CustomerPolicies)
	}
	got := statusText(t, rep)
	for _, want := range []string{
		"  Your Tetragon policies (DefenseClaw reads their events and never changes them):\n",
		"    NAME               MODE     STATE       EVENTS  FORWARDED  BLOCKED  LAST\n",
		"    10-file-sensitive  enforce  enabled     120     12         2        2026-10-07T11:58:00Z\n",
		"    20-net-connect     monitor  enabled     40      3          0        -\n",
		"    30-removed         -        not listed  5       1          0        -\n",
		"  ! " + codeCustomerEventsCapped + ":20-net-connect: 7 events of your Tetragon policy 20-net-connect were not forwarded in the last hour",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("text lacks %q:\n%s", want, got)
		}
	}
	verify := RunTetragonVerify(context.Background(), h.env, "consume")
	if check := checkOf(t, verify, checkTetragonYourPolicy); !strings.Contains(check.Message, "2 of your Tetragon policies are loaded (1 enforcing)") {
		t.Fatalf("your policies check %+v", check)
	}
	if check := checkOf(t, verify, checkHealthLoopback); check.Status != checkWarn {
		t.Fatalf("health on every interface: %+v", check)
	}
}
