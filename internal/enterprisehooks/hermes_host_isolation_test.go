// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
)

// TestMain runs the package's tests off the host's Hermes setup
// (hermespath.IsolateHostForTests): a HERMES_HOME a Hermes developer
// exported made install refuse a hook config outside the test home.
func TestMain(m *testing.M) {
	cleanup, err := hermespath.IsolateHostForTests()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolate the tests from the host's Hermes:", err)
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// Run with HERMES_HOME exported, the tests still see none.
func TestEnterpriseHooksTestsRunWithoutTheHostsHermesEnvironment(t *testing.T) {
	for _, variable := range os.Environ() {
		if strings.HasPrefix(variable, "HERMES_") {
			t.Fatalf("the tests run with the host's %s", variable)
		}
	}
}
