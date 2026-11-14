// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package hookcli

import (
	"fmt"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestMain keeps the hook tests off the computer they run on, as the
// internal/cli TestMain did before the hook commands moved here: the host
// Hermes install, the real per-user folders (GAP-0887), the Claude Code
// chain, and on Windows the managed markers, the Secure Client
// classification, the runtime descriptor and the deployment roots.
func TestMain(m *testing.M) {
	cleanupHermes, err := hermespath.IsolateHostForTests()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolate the tests from the host Hermes:", err)
		os.Exit(1)
	}
	finishUserRoots, err := testenv.IsolateUserRoots()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolate the tests from the real per-user folders:", err)
		os.Exit(1)
	}
	// The account home the outage mode reads comes from the account
	// database, not HOME: on a build box whose own account has a
	// ~/.defenseclaw/config.yaml the tests read that config (GAP-0345 class).
	// Tests that need an account home set their own.
	accountHome, err := os.MkdirTemp("", "defenseclaw-hookcli-account-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "make the test account home:", err)
		os.Exit(1)
	}
	previousAccountHome := OutageAccountHome
	OutageAccountHome = func() string { return accountHome }
	restoreChain := connector.UseClaudeCodeChainFixtureForTests()
	restoreHost := isolateHookTestHost()
	code := m.Run()
	restoreHost()
	restoreChain()
	OutageAccountHome = previousAccountHome
	_ = os.RemoveAll(accountHome)
	cleanupHermes()
	if err := finishUserRoots(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}
