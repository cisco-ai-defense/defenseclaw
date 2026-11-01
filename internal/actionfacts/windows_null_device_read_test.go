// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// GAP-2408: the NUL device as a read source names no file, so it leaves the
// facts complete and the redirect stays the exact write it is.
func TestWindowsNullDeviceReadKeepsTheRedirectWriteExact(t *testing.T) {
	for _, dialect := range []Dialect{DialectCMD, DialectPowerShell} {
		for _, command := range []string{`type nul > C:\work\f.txt`, `type NUL: >> C:\work\f.txt`} {
			facts := Analyze(Input{Tool: "Bash", Command: command, CWD: `C:\work`, DialectHint: dialect})
			projection := facts.EnforcementProjection()
			if !projection.Authoritative() || !projection.EnforcementEligible() {
				t.Errorf("%s %q: facts not authoritative: %+v", dialect, command, facts.Parse)
			}
			writes := 0
			for _, p := range projection.Paths {
				if p.Access == PathAccessRead {
					t.Errorf("%s %q: NUL kept as a read path %+v", dialect, command, p)
				}
				if p.Access == PathAccessWrite || p.Access == PathAccessAppend {
					writes++
				}
			}
			if writes != 1 {
				t.Errorf("%s %q: %d write or append paths, want 1: %+v", dialect, command, writes, projection.Paths)
			}
		}
	}
}
