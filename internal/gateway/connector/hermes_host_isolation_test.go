// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestMain runs the package's tests off the host's Hermes setup
// (hermespath.IsolateHostForTests): a HERMES_HOME a Hermes developer
// exported failed the Hermes Setup and Verify tests.
func TestMain(m *testing.M) {
	answerAsFakeGuard()
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
	prepareConnectorTestProcess()
	secureClientAdded := guardSecureClientTree()
	cleanup, err := hermespath.IsolateHostForTests()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolate the tests from the host's Hermes:", err)
		os.Exit(1)
	}
	// The tests never write the real per-user vendor folders (GAP-0887).
	finishUserRoots, err := testenv.IsolateUserRoots()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolate the tests from the real per-user folders:", err)
		os.Exit(1)
	}
	restoreChain := UseClaudeCodeChainFixtureForTests()
	code := m.Run()
	restoreChain()
	cleanup()
	if err := finishUserRoots(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	// The tests never write the real Cisco Secure Client folders (GAP-0780).
	if added := secureClientAdded(); len(added) > 0 {
		fmt.Fprintln(os.Stderr, "the tests left entries in the real Cisco Secure Client folders; a test must use a temp layout or a layout seam:")
		for _, path := range added {
			fmt.Fprintln(os.Stderr, "  "+path)
		}
		code = 1
	}
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
