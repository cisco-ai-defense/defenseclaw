// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"strings"
)

// sanitizedTestEnv returns os.Environ() with every DEFENSECLAW_* entry
// removed. Hook shell scripts read a small pile of env vars
// (DEFENSECLAW_FAIL_MODE, DEFENSECLAW_STRICT_AVAILABILITY,
// DEFENSECLAW_MANAGED_HOOK, DEFENSECLAW_GATEWAY_TOKEN,
// DEFENSECLAW_HOOK_CONNECTOR, DEFENSECLAW_HOOK_NAME,
// DEFENSECLAW_HOOK_MAX_BODY, DEFENSECLAW_HOME, …) and any of them set
// in a developer shell or CI job leaks into `cmd.Env = append(os.Environ(), …)`
// test helpers and silently overrides the fail-mode / strictness the
// test intended. That surfaces as spurious "expected exit 0 (fail-open),
// got exit status 2" failures the caller has no way to diagnose from
// the diff alone (been-there-hit-that: `DEFENSECLAW_FAIL_MODE=closed`
// exported in a dev shell → every cursor / codex / claude fail-open
// test failed locally while CI green).
//
// Tests that intentionally exercise one of these vars must append it
// AFTER this helper (`append(sanitizedTestEnv(), "DEFENSECLAW_FAIL_MODE=closed")`).
// PATH, HOME, USERPROFILE, and every non-DefenseClaw var pass through
// unchanged so the shell can still find bash, curl, sed, etc.
func sanitizedTestEnv() []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	for _, entry := range src {
		if strings.HasPrefix(entry, "DEFENSECLAW_") {
			continue
		}
		out = append(out, entry)
	}
	return out
}
