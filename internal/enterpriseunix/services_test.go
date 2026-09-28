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
	"sort"
	"strings"
	"testing"

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
