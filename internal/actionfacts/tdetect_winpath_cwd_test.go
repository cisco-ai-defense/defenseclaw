// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestStructuredToolDrivePathReadings pins the two readings of a drive-letter
// or UNC value named by a structured file tool. With no working folder it is
// the absolute Windows path (rel-1-0-10:GAP-0872). A trusted POSIX working
// folder supplies the POSIX syntax, so the same value is a relative name below
// that folder, which a .. climb can take into the home (rel-1-0-10:GAP-0895):
// that POSIX reading is never replaced by the Windows one. The /llm route,
// which judges in a neutral POSIX folder, also judges rel's bare reading and
// keeps the stronger verdict (gateway proxyBareReading).
func TestStructuredToolDrivePathReadings(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{`C:\Users\x\.aws\credentials`, "C:/Users/x/.aws/credentials"},
		{`C:/Users/x/.netrc`, "C:/Users/x/.netrc"},
		{`\\server\share\x\.netrc`, ""},
	} {
		args, _ := json.Marshal(map[string]string{"file_path": tc.value})
		facts := Analyze(Input{Tool: "Read", Args: args, ActiveHome: "/home/alice"})
		if len(facts.Paths) != 1 {
			t.Fatalf("%q no cwd: %d paths", tc.value, len(facts.Paths))
		}
		got := facts.Paths[0]
		if got.Flavor != PathFlavorWindows || (tc.want != "" && got.Resolved != tc.want) {
			t.Errorf("%q no cwd: flavor %v resolved %q, want the Windows path %q", tc.value, got.Flavor, got.Resolved, tc.want)
		}
		const cwd = "/home/alice/proj"
		facts = Analyze(Input{Tool: "Read", Args: args, CWD: cwd, ActiveHome: "/home/alice"})
		if len(facts.Paths) != 1 {
			t.Fatalf("%q cwd %q: %d paths", tc.value, cwd, len(facts.Paths))
		}
		got = facts.Paths[0]
		if got.Flavor != PathFlavorPOSIX || !strings.HasPrefix(got.Resolved, cwd+"/") {
			t.Errorf("%q cwd %q: flavor %v resolved %q, want the POSIX name below the working folder", tc.value, cwd, got.Flavor, got.Resolved)
		}
	}
}
