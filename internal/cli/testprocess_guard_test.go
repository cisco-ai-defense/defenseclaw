// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// testProcessState is the process-wide state a test can change for every
// test after it: the environment, the working folder and (on Windows) the
// CPU priority class.
type testProcessState struct {
	env      map[string]string
	cwd      string
	priority string
}

func readTestProcessState() testProcessState {
	state := testProcessState{env: map[string]string{}, priority: testProcessPriority()}
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if name == "" {
			// Windows keeps per-drive working folders as "=C:" entries.
			continue
		}
		state.env[name] = value
	}
	state.cwd, _ = os.Getwd()
	return state
}

// diffTestProcessState names what changed, never the values: an
// environment value can be a credential.
func diffTestProcessState(before, after testProcessState) []string {
	var changes []string
	for name, value := range before.env {
		if now, ok := after.env[name]; !ok {
			changes = append(changes, "environment "+name+" removed")
		} else if now != value {
			changes = append(changes, "environment "+name+" changed")
		}
	}
	for name := range after.env {
		if _, ok := before.env[name]; !ok {
			changes = append(changes, "environment "+name+" added")
		}
	}
	sort.Strings(changes)
	if before.cwd != after.cwd {
		changes = append(changes, fmt.Sprintf("working folder %s -> %s", before.cwd, after.cwd))
	}
	if before.priority != after.priority {
		changes = append(changes, fmt.Sprintf("priority class %s -> %s", before.priority, after.priority))
	}
	return changes
}

// testProcessGuardChildEnv marks the test binary's own child processes (the
// helper processes some tests start with os.Args[0]). A helper changes the
// process state on purpose (its priority class, its environment) and exits,
// so only the top-level run is guarded.
const testProcessGuardChildEnv = "DEFENSECLAW_CLI_TEST_GUARDED_PARENT"

// guardTestProcessState fails the run when a test left the process state
// changed: every test after it, in any order, inherited it (GAP-0079).
func guardTestProcessState() func() error {
	if os.Getenv(testProcessGuardChildEnv) != "" {
		return func() error { return nil }
	}
	_ = os.Setenv(testProcessGuardChildEnv, strconv.Itoa(os.Getpid()))
	before := readTestProcessState()
	return func() error {
		changes := diffTestProcessState(before, readTestProcessState())
		if len(changes) == 0 {
			return nil
		}
		return fmt.Errorf("GAP-0079: a test left the process state changed for the tests after it:\n  %s",
			strings.Join(changes, "\n  "))
	}
}

func TestTestProcessStateGuardNamesEveryChange(t *testing.T) {
	before := testProcessState{env: map[string]string{"KEPT": "1", "CHANGED": "1", "REMOVED": "1"}, cwd: "a", priority: "normal"}
	after := testProcessState{env: map[string]string{"KEPT": "1", "CHANGED": "secret", "ADDED": "1"}, cwd: "b", priority: "below normal"}
	got := strings.Join(diffTestProcessState(before, after), "\n")
	want := "environment ADDED added\nenvironment CHANGED changed\nenvironment REMOVED removed\n" +
		"working folder a -> b\npriority class normal -> below normal"
	if got != want {
		t.Fatalf("diff =\n%s\nwant\n%s", got, want)
	}
	if strings.Contains(got, "secret") {
		t.Fatal("the guard printed an environment value")
	}
	if changes := diffTestProcessState(before, before); len(changes) != 0 {
		t.Fatalf("an unchanged state reported %v", changes)
	}
}

// keepTestOffTheRealDataHome moves the home of one test to a folder of its
// own. A config write validates the candidate and loads the .env of the data
// folder into the process environment (config.ValidateCandidate), so a test
// that writes config.yaml without its own home read the .env of the account
// that runs the tests and left its keys set for every test after it. On a
// host whose account has a .env that failed the run guard above; only a
// native Windows standard-user run had one (GAP-2174).
func keepTestOffTheRealDataHome(t *testing.T) {
	t.Helper()
	testenv.SetHome(t, t.TempDir())
	t.Setenv("DEFENSECLAW_HOME", "")
}
