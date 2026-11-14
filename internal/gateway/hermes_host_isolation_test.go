// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestMain(m *testing.M) {
	prepareGatewayTestProcess()
	// No test reads the host's shell startup or system profiles (GAP-0293).
	testenv.ClearShellStartup()
	hookpaths.UseSystemShellProfilesForTests(nil, "")
	// A call never waits for a start that is not coming; the gate's tests
	// (TestSessionStartGateCallBeforeItsStart) set the arrival wait.
	sessionStartArrivalWait = 0
	// The fail-open report reads only the test's data directory, never the
	// host account's ~/.defenseclaw/logs (hookFailuresHooksHome).
	hookFailuresHooksHome = func() string { return "" }
	cleanup, err := hermespath.IsolateHostForTests()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolate the tests from the host's Hermes:", err)
		os.Exit(1)
	}
	finishUserRoots, err := testenv.IsolateUserRoots()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolate the tests from the real per-user folders:", err)
		os.Exit(1)
	}
	// An empty home for the whole process: no test reads the account's
	// instruction files or agent folders (environment sweep, GAP-0396).
	restoreHome, err := testenv.IsolateProcessHome()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolate the tests from the account home:", err)
		os.Exit(1)
	}
	restoreChain := connector.UseClaudeCodeChainFixtureForTests()
	code := m.Run()
	restoreChain()
	restoreHome()
	removeMigratedAuditTemplate()
	cleanup()
	if err := finishUserRoots(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

// Run with HERMES_HOME and another HERMES_* variable exported: gateway tests
// must not see the developer's Hermes configuration or managed directories.
func TestGatewayTestsRunWithoutTheHostsHermesEnvironment(t *testing.T) {
	for _, variable := range os.Environ() {
		if strings.HasPrefix(variable, "HERMES_") {
			t.Fatalf("the tests run with the host's %s", variable)
		}
	}
}
