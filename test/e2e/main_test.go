// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestMain lets native helper executables copied from this test binary handle
// their protocol before the Go test harness starts the e2e suite recursively.
// On non-Windows hosts runCodexPolicyFixtureIfRequested is a no-op.
func TestMain(m *testing.M) {
	if handled, exitCode := runCodexPolicyFixtureIfRequested(); handled {
		os.Exit(exitCode)
	}
	// Setup for Claude Code on Windows needs the hook guard a packaged install has.
	restoreChain := connector.UseClaudeCodeChainFixtureForTests()
	code := m.Run()
	restoreChain()
	os.Exit(code)
}
