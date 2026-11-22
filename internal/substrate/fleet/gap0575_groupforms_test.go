// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"strings"
	"testing"
)

// GAP-0575 (GAP-0568 P4 items): DOMAIN\name and SID values are host-side
// forms (an AD-joined launcher matches them), not a token form, so they
// get no "more than one form" or "matches nobody" warning; a blank token
// group does not set the token's form or the example.
func TestGAP0575GroupFormsSkipHostFormsAndBlankGroups(t *testing.T) {
	kc := []string{"/eng", "/ops"}
	for name, c := range map[string]struct {
		groups []string
		token  []string
	}{
		"K06 CORP\\Engineers beside /eng":   {[]string{`CORP\Engineers`, "/eng"}, kc},
		"K07 a SID against a path token":    {[]string{"S-1-5-21-1004336348-1177238915-682003330-512"}, kc},
		"K08 CORP\\Engineers, a path token": {[]string{`CORP\Engineers`}, kc},
		"K10 blank token group first":       {[]string{"/eng"}, []string{"", "/eng"}},
	} {
		if got := GroupFormMismatches([]ProfileGroups{{Profile: "eng", Groups: c.groups}}, c.token); len(got) != 0 {
			t.Errorf("%s: %q, want no warning", name, got)
		}
	}
	// A real mismatch still warns, with a non-blank example.
	got := GroupFormMismatches([]ProfileGroups{{Profile: "eng", Groups: []string{"Engineers"}}}, []string{" ", "/eng"})
	if len(got) != 1 || !strings.Contains(got[0], "such as /eng") {
		t.Errorf("name against a path token: %q", got)
	}
}
