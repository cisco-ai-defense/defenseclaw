// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"testing"
)

// rel-1-0-10 GAP-1745: kiroPathError adds the file to a message only when the
// message does not already name it as a whole path, not as part of a longer
// path (a backup copy, a folder of the same prefix).
func TestKiroPathErrorNamesTheFileOnceAsAWholePath(t *testing.T) {
	const path = "/h/.kiro/agents/mine.json"
	for _, tc := range []struct {
		inner, want string
	}{
		{"parse JSON " + path + ": invalid character", "kiro remove agent hooks: parse JSON " + path + ": invalid character"},
		{"open " + path, "kiro remove agent hooks: open " + path},
		{"cannot read " + path + ".", "kiro remove agent hooks: cannot read " + path + "."},
		{"parse JSON " + path + ".bak: invalid", "kiro remove agent hooks " + path + ": parse JSON " + path + ".bak: invalid"},
		{"parse JSON /x" + path + ": invalid", "kiro remove agent hooks " + path + ": parse JSON /x" + path + ": invalid"},
		{"permission denied", "kiro remove agent hooks " + path + ": permission denied"},
	} {
		if got := kiroPathError("kiro remove agent hooks", path, errors.New(tc.inner)).Error(); got != tc.want {
			t.Errorf("inner %q:\n got  %q\n want %q", tc.inner, got, tc.want)
		}
	}
}
