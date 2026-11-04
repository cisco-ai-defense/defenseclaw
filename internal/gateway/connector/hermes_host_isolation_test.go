// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
)

// TestMain runs the package's tests off the host's Hermes setup
// (hermespath.IsolateHostForTests): a HERMES_HOME a Hermes developer
// exported failed the Hermes Setup and Verify tests.
func TestMain(m *testing.M) {
	// A copy of this test binary stands in for the packaged Windows hook
	// launcher in Hermes' execution-probe tests (testHermesProbeLauncherEnv).
	// "1" answers as the active hook runtime does; any other value is a
	// launcher that runs but gives no proof.
	if mode := os.Getenv(testHermesProbeLauncherEnv); mode != "" && len(os.Args) > 1 &&
		os.Args[len(os.Args)-1] == "--defenseclaw-execution-probe" {
		if mode != "1" {
			os.Exit(3)
		}
		fmt.Print(hermesExecutionProbeResponse)
		os.Exit(0)
	}
	if verdict := os.Getenv(testCoworkLauncherEnv); verdict != "" && len(os.Args) == 4 && os.Args[1] == "hook" {
		runCoworkLauncherStandIn(verdict)
	}
	prepareConnectorTestProcess()
	cleanup, err := hermespath.IsolateHostForTests()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolate the tests from the host's Hermes:", err)
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// testHermesProbeLauncherEnv makes a copy of the test binary answer Hermes'
// execution probe as the active hook runtime does.
const testHermesProbeLauncherEnv = "DC_CONNECTOR_TEST_HERMES_PROBE_LAUNCHER"

// Run with HERMES_HOME exported, the tests still see none.
func TestConnectorTestsRunWithoutTheHostsHermesEnvironment(t *testing.T) {
	for _, variable := range os.Environ() {
		if strings.HasPrefix(variable, "HERMES_") {
			t.Fatalf("the tests run with the host's %s", variable)
		}
	}
}

// testCoworkLauncherEnv makes a copy of the test binary stand in for the
// Windows hook launcher in the Cowork plugin simulation: "deny" answers exit
// 2 with a reason, "allow" exit 0 with an allow decision. It reads the event
// on stdin first, as the launcher does.
const testCoworkLauncherEnv = "DC_CONNECTOR_TEST_COWORK_LAUNCHER"

func runCoworkLauncherStandIn(verdict string) {
	input, _ := io.ReadAll(os.Stdin)
	if !strings.Contains(string(input), "PreToolUse") {
		fmt.Fprintln(os.Stderr, "no event on stdin")
		os.Exit(3)
	}
	if verdict == "deny" {
		fmt.Fprintln(os.Stderr, "DefenseClaw denied this tool call")
		os.Exit(2)
	}
	fmt.Println(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`)
	os.Exit(0)
}
