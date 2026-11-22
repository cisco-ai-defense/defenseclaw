// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// isolateHookOutageAccount makes the outage-mode lookups of a test see no
// account but the test's own. HOME and the DEFENSECLAW_* variables move with
// testenv.IsolateAccount; the account database's home and the installed
// runtime's data root (hookRuntimeConfigPath falls back to them when the data
// directory has no config.yaml) are stubbed to none, since neither follows
// HOME. Without it, a host with a real ~/.defenseclaw/config.yaml (the build
// box) answered "open" where a host without one answers "closed" (GAP-0137).
// A test that needs an account sets stubOutageInstallFolders after it.
func isolateHookOutageAccount(t *testing.T) string {
	t.Helper()
	home := testenv.IsolateAccount(t)
	stubOutageInstallFolders(t, func() string { return "" }, func() (string, bool) { return "", false })
	return home
}
