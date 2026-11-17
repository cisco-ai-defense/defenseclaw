// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"
)

// rel-1-0-10 GAP-1158: status and verify report a marker whose last retire
// ended pending as hook_image_retire_pending (do not run the older Setup),
// and a finished or older marker as hook_image_retired.
func TestHookImageStatusReportsAPendingRetireMarker(t *testing.T) {
	const problem = `the launch folders are retired (C:\Program Files\Cisco\DefenseClaw\bin\hooks\.retired); agent hooks name the transition image`
	read := func(windowsHookImageConfigFile) ([]byte, error) { return nil, errors.New("not read") }
	for _, tc := range []struct {
		name, marker string
		err          error
		want         string
	}{
		{"pending", `{"schema_version":1,"retired_at":"x","state":"pending"}`, nil, windowsHookImageRetirePending},
		{"ok", `{"schema_version":1,"retired_at":"x","state":"ok"}`, nil, "hook_image_retired"},
		{"before the state field", `{"schema_version":1,"retired_at":"x"}`, nil, "hook_image_retired"},
		{"unreadable marker", "", errors.New("access denied"), "hook_image_retired"},
		{"marker that does not parse", `{"schema_version":1,"retired_at":"x","sta`, nil, windowsHookImageRetirePending},
	} {
		issues := windowsHookImageRetiredIssues(problem, []byte(tc.marker), tc.err, hookImageTestBin, read, nil)
		if len(issues) != 1 || issues[0].Code != tc.want {
			t.Errorf("%s: issues = %+v, want one %s", tc.name, issues, tc.want)
			continue
		}
		if tc.want == windowsHookImageRetirePending && (!strings.Contains(issues[0].Text, "Do NOT run an older release's Setup") ||
			!strings.Contains(issues[0].Text, "has not finished")) {
			t.Errorf("pending text = %q", issues[0].Text)
		}
	}
}
