// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// An account that enterprise.enrollment.exclude_users names is not covered by
// any managed hook, so its own status never says protected, and never takes
// the machine-wide state: every connector row, and Cowork, is excluded, with
// the reason in its own field. Enrolled accounts on the same machine keep
// their rows.

func ownStatusExcludedFixture(t *testing.T, exclude []string, agents []enterprisehooks.UnprotectedAgent) *APIServer {
	t.Helper()
	previousGuardian := ownStatusGuardianAuthorization
	ownStatusGuardianAuthorization = func(string) (*managedGuardianAuthorization, string) { return nil, "unavailable" }
	t.Cleanup(func() { ownStatusGuardianAuthorization = previousGuardian })
	completeOwnStatusScan(t, agents)
	enabled := true
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {Enabled: &enabled}, "copilot": {Enabled: &enabled}, "opencode": {Enabled: &enabled},
	}
	cfg.Enterprise.Enrollment.ExcludeUsers = exclude
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	api.managedPolicyView.Store(&managedPolicyView{connectors: map[string]managedPolicyViewConnector{
		"claudecode": {}, "copilot": {}, "opencode": {},
	}})
	return api
}

// requireExcludedAnswer holds an answer to the excluded contract through a
// JSON round trip: every connector row and the Cowork row are in the state
// excluded, not protected, with the code, the reason and the next step.
func requireExcludedAnswer(t *testing.T, answer map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(answer)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ClaudeCode struct {
			Protected bool `json:"protected"`
		} `json:"claude_code"`
		Connectors map[string]map[string]any `json:"connectors"`
		Cowork     map[string]any            `json:"cowork"`
	}
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	if out.ClaudeCode.Protected {
		t.Fatalf("legacy claude_code field says protected for an excluded account: %s", encoded)
	}
	if len(out.Connectors) != 3 {
		t.Fatalf("excluded roster = %v, want the 3 configured connectors: %s", out.Connectors, encoded)
	}
	for name, row := range out.Connectors {
		requireExcludedRow(t, name, row, true)
	}
	// The Cowork row has a reason and no next step.
	requireExcludedRow(t, "cowork", out.Cowork, false)
}

func requireExcludedRow(t *testing.T, name string, row map[string]any, wantNext bool) {
	t.Helper()
	reason, _ := row["reason"].(string)
	next, _ := row["next_step"].(string)
	if row["state"] != "excluded" || row["protected"] != false || row["reason_code"] != "excluded_users" ||
		!strings.Contains(reason, "exclude_users") || wantNext != (next != "") {
		t.Fatalf("%s row = %#v, want state excluded, not protected, with the exclude_users reason and a next step", name, row)
	}
}

func ownStatusRowFor(t *testing.T, api *APIServer, idKey, id, name, connector string) map[string]any {
	t.Helper()
	roster, ok := api.ownStatusAnswer(context.Background(), idKey, id, name)["connectors"].(map[string]any)
	if !ok {
		t.Fatal("own status has no connector roster")
	}
	row, ok := roster[connector].(map[string]any)
	if !ok {
		t.Fatalf("own status has no %s row: %#v", connector, roster)
	}
	return row
}

func TestOwnStatusExcludedAccountIsExcludedOnEveryRow(t *testing.T) {
	v1 := unprotectedAgentFor("carol", 5003, "opencode", enterprisehooks.UnprotectedCodeOpenCodeV1, "OpenCode V1 runs unchecked")
	api := ownStatusExcludedFixture(t, []string{"carol", "5004"}, []enterprisehooks.UnprotectedAgent{v1})

	// By name, and by decimal uid; a scan entry for the account does not
	// change the state, which comes from the exclusion.
	requireExcludedAnswer(t, api.ownStatusAnswer(context.Background(), "uid", "5003", "carol"))
	requireExcludedAnswer(t, api.ownStatusAnswer(context.Background(), "uid", "5004", "dave"))
}

// Enrolled accounts on the same machine keep their current rows: protected
// where the policy view proves it, not protected where the scan lists the
// agent.
func TestOwnStatusEnrolledAccountBesideExcludedAccountIsUnchanged(t *testing.T) {
	v1 := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeOpenCodeV1, "OpenCode V1 runs unchecked")
	api := ownStatusExcludedFixture(t, []string{"carol"}, []enterprisehooks.UnprotectedAgent{v1})

	for _, connector := range []string{"claudecode", "copilot"} {
		if row := ownStatusRowFor(t, api, "uid", "5001", "alice", connector); row["state"] != "protected" || row["protected"] != true {
			t.Fatalf("enrolled alice %s row = %#v, want protected", connector, row)
		}
	}
	if row := ownStatusRowFor(t, api, "uid", "5001", "alice", "opencode"); row["state"] != "not protected" || row["reason_code"] != "scan_unprotected" {
		t.Fatalf("enrolled alice OpenCode V1 row = %#v, want not protected from the scan", row)
	}
	// Another name or uid that only resembles an excluded entry is enrolled.
	for _, tc := range [][2]string{{"5005", "Carol"}, {"5006", "carol2"}, {"50030", "bob"}} {
		if row := ownStatusRowFor(t, api, "uid", tc[0], tc[1], "claudecode"); row["state"] != "protected" {
			t.Fatalf("%s (uid %s) Claude Code row = %#v, want protected", tc[1], tc[0], row)
		}
	}
	if cowork, _ := api.ownStatusAnswer(context.Background(), "uid", "5001", "alice")["cowork"].(map[string]any); cowork["state"] != "protected" {
		t.Fatalf("enrolled alice Cowork row = %#v, want protected", cowork)
	}
}

// Root is never excluded by name or uid: enrollment.root decides its calls.
func TestOwnStatusRootIsNotExcludedByExcludeUsers(t *testing.T) {
	api := ownStatusExcludedFixture(t, []string{"root", "0"}, nil)
	if row := ownStatusRowFor(t, api, "uid", "0", "root", "claudecode"); row["state"] == "excluded" {
		t.Fatalf("root row = %#v, want the root policy row, not excluded", row)
	}
}

// Windows: the entry is the SID, or the account name with or without its
// domain, in any case.
func TestOwnStatusWindowsExcludedAccountIsExcludedOnEveryRow(t *testing.T) {
	const alice, bob = "S-1-5-21-1004336348-1177238915-682003330-1001", "S-1-5-21-1004336348-1177238915-682003330-1002"
	for _, tc := range []struct {
		name    string
		exclude []string
	}{
		{"sid", []string{strings.ToLower(alice)}},
		{"domain name", []string{`win11\ALICE`}},
		{"bare name", []string{"Alice"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := ownStatusExcludedFixture(t, tc.exclude, nil)
			requireExcludedAnswer(t, api.ownStatusAnswer(context.Background(), "sid", alice, `WIN11\alice`))
			// Benign twin: bob is enrolled.
			if row := ownStatusRowFor(t, api, "sid", bob, `WIN11\bob`, "claudecode"); row["state"] == "excluded" {
				t.Fatalf("bob claudecode row = %#v, want not excluded", row)
			}
		})
	}
}

// Windows enrollment also matches the profile folder name, and a qualified
// entry selects one domain (windowsProfileEnrollmentDecision): status says
// excluded exactly when the enumerator removed the account, and enrolled
// otherwise.
func TestOwnStatusWindowsExclusionFollowsTheEnumeratorSpellings(t *testing.T) {
	const alice = "S-1-5-21-1004336348-1177238915-682003330-1001"
	restoreHome := userScopedIdentityHome
	t.Cleanup(func() { userScopedIdentityHome = restoreHome })
	userScopedIdentityHome = func(id string) string {
		if id == alice {
			return `C:\Users\alice.CONTOSO`
		}
		return ""
	}
	for _, tc := range []struct {
		name     string
		exclude  string
		excluded bool
	}{
		{"profile folder name", "Alice.contoso", true},
		{"domain and account", `contoso\ALICE`, true},
		{"other domain, same short name", `OTHER\alice`, false},
		{"profile folder of another account", "bob.CONTOSO", false},
		{"bare account name", "alice", true},
		{"folder stem with other suffix", "alice.OTHER", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := ownStatusExcludedFixture(t, []string{tc.exclude}, nil)
			row := ownStatusRowFor(t, api, "sid", alice, `CONTOSO\alice`, "claudecode")
			if got := row["state"] == "excluded"; got != tc.excluded {
				t.Fatalf("exclude_users [%s]: row = %#v, excluded = %v, want %v", tc.exclude, row, got, tc.excluded)
			}
			if tc.excluded {
				requireExcludedAnswer(t, api.ownStatusAnswer(context.Background(), "sid", alice, `CONTOSO\alice`))
			} else if row["state"] != "protected" {
				t.Fatalf("enrolled row = %#v, want protected", row)
			}
		})
	}
}

// The Windows pipe names the caller by the bare account name, so the
// DOMAIN\account spelling the enumerator matches comes from the domain the
// LSA names for the SID: the pipe entrypoint excludes exactly the accounts the
// enumerator removed, and leaves the others enrolled.
func TestOwnStatusWindowsPipeEntrypointExcludesTheQualifiedSpelling(t *testing.T) {
	const alice = "S-1-5-21-1004336348-1177238915-682003330-1001"
	previousName, previousDomain, previousHome := ownStatusWindowsAccountName, ownStatusWindowsAccountDomain, userScopedIdentityHome
	t.Cleanup(func() {
		ownStatusWindowsAccountName, ownStatusWindowsAccountDomain, userScopedIdentityHome = previousName, previousDomain, previousHome
	})
	ownStatusWindowsAccountName = func(string) string { return "alice" }
	ownStatusWindowsAccountDomain = func(string) string { return "CONTOSO" }
	userScopedIdentityHome = func(string) string { return `C:\Users\alice` }
	for _, tc := range []struct {
		exclude  string
		excluded bool
	}{
		{`CONTOSO\alice`, true},
		{`contoso\ALICE`, true},
		{"alice", true},
		{`OTHER\alice`, false},
		{`CONTOSO\bob`, false},
	} {
		t.Run(tc.exclude, func(t *testing.T) {
			api := ownStatusExcludedFixture(t, []string{tc.exclude}, nil)
			var answer map[string]any
			if err := json.Unmarshal(api.ownStatusForWindowsAccount(context.Background(), alice), &answer); err != nil {
				t.Fatal(err)
			}
			connectors, _ := answer["connectors"].(map[string]any)
			row, _ := connectors["claudecode"].(map[string]any)
			if got := row["state"] == "excluded"; got != tc.excluded {
				t.Fatalf("exclude_users [%s]: claudecode row = %#v, excluded = %v, want %v", tc.exclude, row, got, tc.excluded)
			}
			if legacy, _ := answer["claude_code"].(map[string]any); tc.excluded && legacy["protected"] != false {
				t.Fatalf("excluded account legacy claude_code = %#v, want protected false", legacy)
			}
			if !tc.excluded && row["state"] != "protected" {
				t.Fatalf("enrolled row = %#v, want protected", row)
			}
		})
	}
}
