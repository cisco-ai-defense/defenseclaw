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
	"errors"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	launchdstandalone "github.com/defenseclaw/defenseclaw/packaging/launchd-standalone"
	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

// The lifecycle manages exactly the reviewed unit files that ship in the
// repository and packages: a unit added to one side only would either never
// be installed or never be stopped.
func TestManagedUnitsMatchEmbeddedDefinitions(t *testing.T) {
	names := func(units []Unit) []string {
		out := make([]string, 0, len(units))
		for _, unit := range units {
			out = append(out, unit.Name)
		}
		sort.Strings(out)
		return out
	}
	if got, want := names(linuxUnits), systemdunits.Units(); !reflect.DeepEqual(got, want) {
		t.Fatalf("linux units %v, embedded %v", got, want)
	}
	if got, want := names(darwinUnits), launchdstandalone.Labels(); !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin units %v, embedded %v", got, want)
	}
}

// Activation order: sensor helper, then the gateway sockets and gateway,
// then the guardian and enumerator.
func TestActivationStagesFollowDependencies(t *testing.T) {
	stage := map[string]int{}
	for _, unit := range linuxUnits {
		stage[unit.Name] = unit.Stage
	}
	order := []string{unitSensorHelper, unitGateway, unitGuardian, unitEnumerator}
	for i := 1; i < len(order); i++ {
		if stage[order[i-1]] >= stage[order[i]] {
			t.Fatalf("%s (stage %d) must activate before %s (stage %d)", order[i-1], stage[order[i-1]], order[i], stage[order[i]])
		}
	}
}

// launchctlPrintRunner answers `launchctl print system/<label>` with the
// canned state of each label.
type launchctlPrintRunner struct{ states map[string]string }

func (r launchctlPrintRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	if name == "launchctl" && len(args) == 2 && args[0] == "print" {
		label := strings.TrimPrefix(args[1], "system/")
		if state, ok := r.states[label]; ok {
			return CommandResult{Stdout: []byte(label + " = {\n\tactive count = 0\n\tstate = " + state + "\n\truns = 1\n}\n")}, nil
		}
	}
	return CommandResult{ExitCode: 113}, errors.New("launchctl print: exit 113: Could not find service")
}

// teardownRunner is launchd finishing a bootout after bootout returned: the
// job stays listed (SIGTERMed) for a few prints, and bootstrap or kickstart
// fails with EALREADY until it is gone.
type teardownRunner struct {
	printsLeft int
	calls      []string
}

func (r *teardownRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	r.calls = append(r.calls, args[0])
	switch args[0] {
	case "print":
		if r.printsLeft > 0 {
			r.printsLeft--
			return CommandResult{Stdout: []byte("state = SIGTERMed\n")}, nil
		}
		return CommandResult{ExitCode: 113}, errors.New("launchctl print: exit 113: Could not find service")
	case "bootstrap", "kickstart":
		if r.printsLeft > 0 {
			return CommandResult{ExitCode: 37}, errors.New("launchctl " + args[0] + ": exit 37: ")
		}
	}
	return CommandResult{}, nil
}

// A config change on macOS left the gateway unloaded: bootout returned while
// launchd was still terminating the gateway, and the bootstrap and the
// kickstart -k fallback both failed with exit 37.
func TestLaunchdStopWaitsForTeardownBeforeStart(t *testing.T) {
	gateway := Unit{Name: labelGateway, Kind: "gateway"}
	restore := launchdTeardownWait
	defer func() { launchdTeardownWait = restore }()

	runner := &teardownRunner{printsLeft: 3}
	manager := &launchdManager{env: &Env{GOOS: "darwin", Runner: runner, PollInterval: time.Millisecond}}
	if err := manager.Stop(context.Background(), gateway); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background(), gateway); err != nil || contains(runner.calls, "kickstart") {
		t.Fatalf("start after stop: %v (calls %v), want a bootstrap once the job is gone", err, runner.calls)
	}

	// Stop gave up waiting: Start waits for its own bootout to finish.
	launchdTeardownWait = 0
	runner = &teardownRunner{printsLeft: 2}
	manager = &launchdManager{env: &Env{GOOS: "darwin", Runner: runner, PollInterval: time.Millisecond}}
	_ = manager.Stop(context.Background(), gateway)
	launchdTeardownWait = time.Minute
	if err := manager.Start(context.Background(), gateway); err != nil || contains(runner.calls, "kickstart") {
		t.Fatalf("start after an unfinished stop: %v (calls %v)", err, runner.calls)
	}

	// A job this manager did not boot out keeps the kickstart fallback, with
	// no wait.
	runner = &teardownRunner{printsLeft: 1}
	manager = &launchdManager{env: &Env{GOOS: "darwin", Runner: runner, PollInterval: time.Millisecond}}
	_ = manager.Start(context.Background(), gateway)
	if !slices.Equal(runner.calls, []string{"bootstrap", "kickstart"}) {
		t.Fatalf("start of a job it did not stop: calls %v", runner.calls)
	}
}

// `enterprise macos status` printed the on-demand apply and verify jobs as
// "not" (the first word of launchctl's "not running").
func TestLaunchdStatusRendersFullJobStates(t *testing.T) {
	env := &Env{GOOS: "darwin", Layout: mustLayout(t, "darwin"), Runner: launchctlPrintRunner{states: map[string]string{
		labelApply:      "not running",
		labelVerify:     "not running",
		labelGateway:    "running",
		labelGuardian:   "not running",
		labelEnumerator: "spawn scheduled",
	}}}
	manager := &launchdManager{env: env}
	want := map[string]string{
		labelApply:        "on demand, idle",
		labelVerify:       "scheduled, idle",
		labelGateway:      "running",
		labelGuardian:     "not running",
		labelEnumerator:   "spawn scheduled",
		labelSensorHelper: "not_loaded",
	}
	for _, unit := range darwinUnits {
		status, err := manager.Status(context.Background(), unit)
		if err != nil {
			t.Fatal(err)
		}
		if status.State != want[unit.Name] {
			t.Fatalf("%s state = %q, want %q", unit.Name, status.State, want[unit.Name])
		}
	}
	for label, active := range map[string]bool{labelApply: true, labelVerify: true, labelGateway: true, labelGuardian: false, labelSensorHelper: false} {
		for _, unit := range darwinUnits {
			if unit.Name == label && manager.Active(context.Background(), unit) != active {
				t.Fatalf("%s active = %v, want %v", label, !active, active)
			}
		}
	}
}

// printDisabledRunner answers `launchctl print-disabled system` with output
// and records every launchctl call.
type printDisabledRunner struct {
	output string
	calls  *[]string
}

func (r printDisabledRunner) Run(_ context.Context, _ string, args ...string) (CommandResult, error) {
	*r.calls = append(*r.calls, strings.Join(args, " "))
	if args[0] == "print-disabled" {
		return CommandResult{Stdout: []byte(r.output)}, nil
	}
	return CommandResult{}, nil
}

// GAP-1443: launchctl enable wrote a "=> enabled" override for each label on
// every install, and no command deletes one, so uninstall left six entries
// in launchd's disabled-services database. Enable now only clears a
// disabled override.
func TestLaunchdEnableClearsOnlyADisabledOverride(t *testing.T) {
	gateway := Unit{Name: labelGateway, Kind: "gateway"}
	for name, tc := range map[string]struct {
		output string
		enable bool
	}{
		"no override":       {"disabled services = {\n\t\"com.apple.ftpd\" => disabled\n}\n", false},
		"enabled override":  {"disabled services = {\n\t\"" + labelGateway + "\" => enabled\n}\n", false},
		"disabled override": {"disabled services = {\n\t\"" + labelGateway + "\" => disabled\n}\n", true},
		"older macOS":       {"disabled services = {\n\t\"" + labelGateway + "\" => true\n}\n", true},
		"another label":     {"disabled services = {\n\t\"" + labelGateway + ".old\" => disabled\n}\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			var calls []string
			manager := &launchdManager{env: &Env{GOOS: "darwin", Runner: printDisabledRunner{output: tc.output, calls: &calls}}}
			if err := manager.Enable(context.Background(), gateway); err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(calls, "enable system/"+labelGateway); got != tc.enable {
				t.Fatalf("enable called = %v, want %v (calls %v)", got, tc.enable, calls)
			}
		})
	}
}
