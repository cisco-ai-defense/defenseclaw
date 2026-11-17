// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// windowsHookImageAuditActorPattern is the form the audit record keeps as
// the actor (internal/audit controlPlaneV8PrincipalPattern): an actor in
// another form is dropped from the record.
var windowsHookImageAuditActorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

// rel-1-0-10 GAP-0906: the HIGH audit row of a --skip-profile named nobody.
// Its actor was the display form "DOMAIN\name (SID)", which the audit record
// drops, and before_state.account was empty because the standalone manifest
// has no user. The row now carries the skipping account as an audit actor
// and in after_state.skipped_by, and the account of the profile.
func TestHookImageRetireSkipAuditRowNamesWhoSkippedAndTheAccount(t *testing.T) {
	profile := windowsHookImageSkippedProfile{
		SID: skipTestSID, Account: windowsHookImageProfileAccount("", `C:\Users\dcw-std2`, nil), Home: `C:\Users\dcw-std2`,
		SkippedBy: `HOST\Administrator (S-1-5-21-1-2-3-500)`, SkippedAt: "2026-11-15T16:20:44Z",
		Files: []windowsHookImageNamedFile{{File: skipTestFile, Folder: "f2e64f2160900a55", Account: true}},
	}
	actor := configwrite.CurrentOSActor()
	payload := windowsHookImageRetireSkipActivity(profile, actor)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var row struct {
		Kind     string `json:"kind"`
		Activity struct {
			Actor      string         `json:"actor"`
			Action     string         `json:"action"`
			TargetType string         `json:"target_type"`
			TargetID   string         `json:"target_id"`
			Severity   string         `json:"severity"`
			Before     map[string]any `json:"before"`
			After      map[string]any `json:"after"`
		} `json:"activity"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatal(err)
	}
	a := row.Activity
	if row.Kind != "activity" || a.Action != "config-update" || a.TargetType != "hook-image-retire-skip" || a.TargetID != skipTestSID || a.Severity != "HIGH" {
		t.Fatalf("row = %s", raw)
	}
	if a.Actor != actor || !strings.HasPrefix(a.Actor, "os:") || !windowsHookImageAuditActorPattern.MatchString(a.Actor) {
		t.Errorf("actor %q is not an audit actor the record keeps", a.Actor)
	}
	if a.After["skipped_by"] != profile.SkippedBy || a.After["skipped_at"] != profile.SkippedAt || a.After["retired"] != false {
		t.Errorf("after_state = %v, want skipped_by %q", a.After, profile.SkippedBy)
	}
	if a.Before["account"] != "dcw-std2" {
		t.Errorf("before_state.account = %v, want the profile folder's account", a.Before["account"])
	}
}

func TestHookImageProfileAccountFallsBackToTheSIDThenTheProfileFolder(t *testing.T) {
	for _, tc := range []struct {
		user, home, lookup, want string
	}{
		{`HOST\dcw-std2`, `C:\Users\dcw-std2`, `HOST\other`, `HOST\dcw-std2`},
		{"", `C:\Users\dcw-std2`, `HOST\dcw-std2`, `HOST\dcw-std2`},
		{" ", `C:\Users\dcw-std2\`, "", "dcw-std2"},
		{"", "", "", ""},
	} {
		got := windowsHookImageProfileAccount(tc.user, tc.home, func() string { return tc.lookup })
		if got != tc.want {
			t.Errorf("account(%q, %q, %q) = %q, want %q", tc.user, tc.home, tc.lookup, got, tc.want)
		}
	}
}
