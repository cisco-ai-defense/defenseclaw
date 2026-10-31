// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
)

func TestMain(m *testing.M) {
	prepareGatewayTestProcess()
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
	code := m.Run()
	cleanup()
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
