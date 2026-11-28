// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"fmt"
	"os"
)

// RequireElevatedEnv set to 1 makes RequireElevated fail, instead of skip, a
// test that runs without an administrator token. Windows Native CI runs
// elevated and sets GITHUB_ACTIONS=true, which has the same effect; a gate
// that must run the elevated twin of a Limited row sets this.
const RequireElevatedEnv = "CI_REQUIRE_ELEVATED"

// elevationStrict reports whether a missing administrator token is a
// failure: GitHub Actions (the Windows runner is elevated) or an explicit
// CI_REQUIRE_ELEVATED=1.
func elevationStrict() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv(RequireElevatedEnv) == "1"
}

// elevationOutcome decides what a test that needs an administrator token does
// on a token that has (or lacks) one: "" runs, "skip" skips with the returned
// reason, "fail" fails with it. Split from RequireElevated so the decision
// is tested on every OS.
func elevationOutcome(haveAdministrator, strict bool, why string) (action, reason string) {
	if haveAdministrator {
		return "", ""
	}
	if strict {
		return "fail", fmt.Sprintf("this test needs an administrator token and the run has none (%s=1 or GitHub Actions requires it): %s", RequireElevatedEnv, why)
	}
	return "skip", fmt.Sprintf("needs an administrator token (an elevated administrator or LocalSystem runs it; the Limited standard-user row skips): %s", why)
}
