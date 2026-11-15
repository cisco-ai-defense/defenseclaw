// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

// TestStructuredToolDrivePathIgnoresAPOSIXWorkingFolder (rel-1-0-10:GAP-0872):
// a drive-letter or UNC path named by a structured file tool is that absolute
// Windows path whatever the working folder is. The proxy judges a model reply's
// tool call in a neutral POSIX folder; the drive path was read as a relative
// name below it and no credential rule matched.
func TestStructuredToolDrivePathIgnoresAPOSIXWorkingFolder(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{`C:\Users\x\.aws\credentials`, "C:/Users/x/.aws/credentials"},
		{`C:/Users/x/.netrc`, "C:/Users/x/.netrc"},
		{`\\server\share\x\.netrc`, ""},
	} {
		args, _ := json.Marshal(map[string]string{"file_path": tc.value})
		for _, cwd := range []string{"", "/tmp/defenseclaw-proxy-cwd-1", "/home/alice/proj"} {
			facts := Analyze(Input{Tool: "Read", Args: args, CWD: cwd, ActiveHome: "/home/alice"})
			if len(facts.Paths) != 1 {
				t.Fatalf("%q cwd %q: %d paths", tc.value, cwd, len(facts.Paths))
			}
			got := facts.Paths[0]
			if got.Flavor != PathFlavorWindows || (tc.want != "" && got.Resolved != tc.want) {
				t.Errorf("%q cwd %q: flavor %v resolved %q, want a Windows path %q", tc.value, cwd, got.Flavor, got.Resolved, tc.want)
			}
			if cwd != "" && len(got.Resolved) > len(cwd) && got.Resolved[:len(cwd)] == cwd {
				t.Errorf("%q cwd %q: resolved below the working folder: %q", tc.value, cwd, got.Resolved)
			}
		}
	}
}
