// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermespath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-0499: a HERMES_HOME the DefenseClaw hooks recorded the account's
// agents running with, or a HOME the Hermes hook ran with, names a Hermes
// home a check of the resolved one does not prove.
func TestVerifyAccountHomeFailsOnARecordedRedirect(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(OverrideAccountEnvironmentForTest(filepath.Join(root, "system")))
	home := filepath.Join(root, "alice")
	resolved := filepath.Dir(ConfigPathForUserHome(home))
	other := filepath.Join(home, "work-hermes")
	record := filepath.Join(home, ".defenseclaw", "foreign-hook-env.json")
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAccountHome(home, resolved, time.Time{}); err != nil {
		t.Fatalf("no evidence: %v", err)
	}
	for _, tc := range []struct {
		name, record, want string
	}{
		{"another connector's HERMES_HOME", `{"v":1,"connectors":{"claudecode":[{"vars":{"HERMES_HOME":` + jsonString(other) + `}}]}}`, other},
		{"the Hermes hook's HERMES_HOME", `{"v":1,"connectors":{"hermes":[{"vars":{"HERMES_HOME":` + jsonString(other) + `}}]}}`, other},
		{"a record that does not parse", `{"v":1,`, "parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(record, []byte(tc.record), 0o600); err != nil {
				t.Fatal(err)
			}
			err := VerifyAccountHome(home, resolved, time.Time{})
			if err == nil || !strings.Contains(err.Error(), "HERMES_HOME unproven") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyAccountHome = %v, want unproven naming %q", err, tc.want)
			}
		})
	}
	if err := os.WriteFile(record, []byte(`{"v":1,"connectors":{"claudecode":[{"vars":{"HERMES_HOME":`+jsonString(resolved)+`}}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAccountHome(home, resolved, time.Time{}); err != nil {
		t.Fatalf("a recorded HERMES_HOME that is the resolved home: %v", err)
	}
}

func jsonString(value string) string {
	return `"` + strings.ReplaceAll(value, `\`, `\\`) + `"`
}

// A redirect counts until a Setup of the home supersedes it: one the hooks
// last saw RecordRefreshInterval or more before that Setup has not been
// seen since (a hook that sees it again refreshes it), so it no longer
// fails. One seen later, or less than that before Setup, or with no
// readable time, still does: a `HERMES_HOME=/tmp/h hermes` run kept Hermes
// unverified forever.
func TestVerifyAccountHomeIgnoresARedirectASetupSuperseded(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(OverrideAccountEnvironmentForTest(filepath.Join(root, "system")))
	home := filepath.Join(root, "alice")
	resolved := filepath.Dir(ConfigPathForUserHome(home))
	other := filepath.Join(root, "tmp-hermes")
	record := filepath.Join(home, ".defenseclaw", "foreign-hook-env.json")
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		t.Fatal(err)
	}
	setUpAt := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	write := func(seen string) {
		t.Helper()
		body := `{"v":1,"connectors":{"hermes":[{"vars":{"HERMES_HOME":` + jsonString(other) + `}` + seen + `}]}}`
		if err := os.WriteFile(record, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stamp := func(at time.Time) string { return `,"seen":"` + at.Format(time.RFC3339) + `"` }

	write(stamp(setUpAt.Add(-RecordRefreshInterval)))
	if err := VerifyAccountHome(home, resolved, setUpAt); err != nil {
		t.Fatalf("a redirect last seen a refresh interval before Setup: %v", err)
	}
	for name, seen := range map[string]string{
		"seen after Setup":                   stamp(setUpAt.Add(time.Minute)),
		"seen less than the interval before": stamp(setUpAt.Add(-RecordRefreshInterval + time.Second)),
		"no time":                            "",
		"an unreadable time":                 `,"seen":"yesterday"`,
	} {
		write(seen)
		if err := VerifyAccountHome(home, resolved, setUpAt); err == nil || !strings.Contains(err.Error(), other) {
			t.Errorf("%s: VerifyAccountHome = %v, want unproven naming %s", name, err, other)
		}
	}
	write(stamp(setUpAt.Add(-48 * time.Hour)))
	if err := VerifyAccountHome(home, resolved, time.Time{}); err == nil || !strings.Contains(err.Error(), other) {
		t.Errorf("no Setup time: VerifyAccountHome = %v, want unproven naming %s", err, other)
	}
}
