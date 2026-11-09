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

func ownStatusExcludedFixture(t *testing.T, exclude []string, agents []enterprisehooks.UnprotectedAgent, configure ...func(*config.Config)) *APIServer {
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
	for _, apply := range configure {
		apply(cfg)
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	api.managedPolicyView.Store(&managedPolicyView{connectors: map[string]managedPolicyViewConnector{
		"claudecode": {}, "copilot": {}, "opencode": {},
	}})
	api.managedHookAuthz.Store(newManagedHookAuthorizer(cfg.Enterprise.Enrollment, []string{"claudecode", "copilot", "opencode"},
		func() (managedHookLedger, error) { return managedHookLedger{}, nil }))
	return api
}

// requireExcludedAnswer holds an answer to the excluded contract through a
// JSON round trip: every connector row and the Cowork row are in the state
// excluded, not protected, with the code, the reason and the next step.
func requireExcludedAnswer(t *testing.T, answer map[string]any, wantCode string) {
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
		requireExcludedRow(t, name, row, wantCode, true)
	}
	// The Cowork row has a reason and no next step.
	requireExcludedRow(t, "cowork", out.Cowork, wantCode, false)
}

func requireExcludedRow(t *testing.T, name string, row map[string]any, wantCode string, wantNext bool) {
	t.Helper()
	reason, _ := row["reason"].(string)
	next, _ := row["next_step"].(string)
	if row["state"] != "excluded" || row["protected"] != false || row["reason_code"] != wantCode ||
		!strings.Contains(reason, "exclude_users") || wantNext != (next != "") {
		t.Fatalf("%s row = %#v, want state excluded, not protected, with the exclude_users reason and a next step", name, row)
	}
}

func ownStatusRowFor(t *testing.T, api *APIServer, idKey, id, name, connector string) map[string]any {
	t.Helper()
	roster, ok := api.ownStatusAnswer(context.Background(), idKey, id, name, "")["connectors"].(map[string]any)
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
	requireExcludedAnswer(t, api.ownStatusAnswer(context.Background(), "uid", "5003", "carol", ""), "excluded_users_inspected")
	requireExcludedAnswer(t, api.ownStatusAnswer(context.Background(), "uid", "5004", "dave", ""), "excluded_users_inspected")
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
	if cowork, _ := api.ownStatusAnswer(context.Background(), "uid", "5001", "alice", "")["cowork"].(map[string]any); cowork["state"] != "protected" {
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
			requireExcludedAnswer(t, api.ownStatusAnswer(context.Background(), "sid", alice, `WIN11\alice`, ""), "excluded_users")
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
				requireExcludedAnswer(t, api.ownStatusAnswer(context.Background(), "sid", alice, `CONTOSO\alice`, ""), "excluded_users")
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
	previousAccount, previousHome := ownStatusWindowsAccount, userScopedIdentityHome
	t.Cleanup(func() { ownStatusWindowsAccount, userScopedIdentityHome = previousAccount, previousHome })
	ownStatusWindowsAccount = func(string) (string, string) { return "alice", "CONTOSO" }
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

// When the LSA does not give the name, or the domain, an exclude_users entry
// is spelled in, the status cannot tell whether the enumerator removed the
// hook for that entry: it claims no protection. Entries it can judge, and an
// account with no entries, keep today's rows.
func TestOwnStatusWindowsPipeUnresolvedAccountClaimsNoProtection(t *testing.T) {
	const alice = "S-1-5-21-1004336348-1177238915-682003330-1001"
	const other = "S-1-5-21-1004336348-1177238915-682003330-1002"
	previousAccount, previousHome := ownStatusWindowsAccount, userScopedIdentityHome
	t.Cleanup(func() { ownStatusWindowsAccount, userScopedIdentityHome = previousAccount, previousHome })
	userScopedIdentityHome = func(string) string { return `C:\Users\alice` }
	for _, tc := range []struct {
		name, account, domain string
		exclude               []string
		want                  string
	}{
		{"qualified entry, domain missing", "alice", "", []string{`CONTOSO\alice`}, "not confirmed"},
		{"name entry, nothing resolved", "", "", []string{"bob"}, "not confirmed"},
		{"folder entry, nothing resolved but the folder", "", "", []string{"alice"}, "excluded"},
		{"qualified entry, nothing resolved", "", "", []string{`CONTOSO\alice`}, "not confirmed"},
		{"qualified entry, name qualified", `CONTOSO\alice`, "", []string{`CONTOSO\alice`}, "excluded"},
		{"name entry, domain missing", "alice", "", []string{"alice"}, "excluded"},
		{"other name entry, domain missing", "alice", "", []string{"bob"}, "protected"},
		{"other qualified entry, domain missing", "alice", "", []string{`OTHER\bob`}, "not confirmed"},
		{"own SID entry, nothing resolved", "", "", []string{alice}, "excluded"},
		{"other SID entry, nothing resolved", "", "", []string{other}, "not confirmed"},
		{"no entries, nothing resolved", "", "", nil, "protected"},
		{"qualified entry, both resolved", "alice", "OTHER", []string{`CONTOSO\alice`}, "protected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ownStatusWindowsAccount = func(string) (string, string) { return tc.account, tc.domain }
			api := ownStatusExcludedFixture(t, tc.exclude, nil)
			var answer map[string]any
			if err := json.Unmarshal(api.ownStatusForWindowsAccount(context.Background(), alice), &answer); err != nil {
				t.Fatal(err)
			}
			connectors, _ := answer["connectors"].(map[string]any)
			cowork, _ := answer["cowork"].(map[string]any)
			legacy, _ := answer["claude_code"].(map[string]any)
			for _, name := range []string{"claudecode", "copilot", "opencode"} {
				row, _ := connectors[name].(map[string]any)
				if tc.want == "protected" && name != "claudecode" {
					continue
				}
				if row["state"] != tc.want {
					t.Fatalf("%s row = %#v, want %s", name, row, tc.want)
				}
				if tc.want == "not confirmed" && row["reason_code"] != "account_unresolved" {
					t.Fatalf("%s row = %#v, want reason_code account_unresolved", name, row)
				}
			}
			if protected := tc.want == "protected"; legacy["protected"] != protected || (cowork["state"] == "protected") != protected {
				t.Fatalf("claude_code = %#v, cowork = %#v, want protected %v", legacy, cowork, protected)
			}
		})
	}
}

// The enumerator also excludes by the profile folder name. When the status
// cannot read the folder, an entry that may be that folder claims no
// protection; an entry that cannot be a folder (a SID, a qualified name), and a
// readable folder, keep their rows.
func TestOwnStatusWindowsPipeUnreadableProfileFolderClaimsNoProtection(t *testing.T) {
	const alice = "S-1-5-21-1004336348-1177238915-682003330-1001"
	const other = "S-1-5-21-1004336348-1177238915-682003330-1002"
	previousAccount, previousHome := ownStatusWindowsAccount, userScopedIdentityHome
	t.Cleanup(func() { ownStatusWindowsAccount, userScopedIdentityHome = previousAccount, previousHome })
	ownStatusWindowsAccount = func(string) (string, string) { return "alice", "CONTOSO" }
	for _, tc := range []struct {
		name, home string
		exclude    []string
		want       string
	}{
		{"folder entry, folder unreadable", "", []string{"alice.CONTOSO"}, "not confirmed"},
		{"arbitrary folder entry, folder unreadable", "", []string{"profile-7"}, "not confirmed"},
		{"folder entry, folder readable", `C:\Users\alice.CONTOSO`, []string{"alice.CONTOSO"}, "excluded"},
		{"other folder entry, folder readable", `C:\Users\alice`, []string{"alice.CONTOSO"}, "protected"},
		{"name entry, folder unreadable", "", []string{"alice"}, "excluded"},
		{"qualified entry, folder unreadable", "", []string{`CONTOSO\alice`}, "excluded"},
		{"other qualified entry, folder unreadable", "", []string{`OTHER\alice`}, "protected"},
		{"other account SID entry, folder unreadable", "", []string{other}, "not confirmed"},
		{"Entra SID entry, folder unreadable", "", []string{"S-1-12-1-123456789-234567890-345678901-456789012"}, "not confirmed"},
		{"other account SID entry, folder readable", `C:\Users\alice`, []string{other}, "protected"},
		{"other account SID entry, SID-named folder readable", `C:\Users\` + other, []string{other}, "excluded"},
		{"own SID entry, folder unreadable", "", []string{"S-1-5-21-1004336348-1177238915-682003330-1001"}, "excluded"},
		{"no entries, folder unreadable", "", nil, "protected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			userScopedIdentityHome = func(string) string { return tc.home }
			api := ownStatusExcludedFixture(t, tc.exclude, nil)
			var answer map[string]any
			if err := json.Unmarshal(api.ownStatusForWindowsAccount(context.Background(), alice), &answer); err != nil {
				t.Fatal(err)
			}
			requireUnresolvedOrState(t, answer, tc.want)
		})
	}
}

// requireUnresolvedOrState holds an answer to one outcome: every checked row,
// the legacy claude_code field and Cowork either are in state want, or, for
// protected, only the Claude Code row is held (the others follow the scan).
func requireUnresolvedOrState(t *testing.T, answer map[string]any, want string) {
	t.Helper()
	connectors, _ := answer["connectors"].(map[string]any)
	cowork, _ := answer["cowork"].(map[string]any)
	legacy, _ := answer["claude_code"].(map[string]any)
	for _, name := range []string{"claudecode", "copilot", "opencode"} {
		row, _ := connectors[name].(map[string]any)
		if want == "protected" && name != "claudecode" {
			continue
		}
		if row["state"] != want {
			t.Fatalf("%s row = %#v, want %s", name, row, want)
		}
		if want == "not confirmed" && row["reason_code"] != "account_unresolved" {
			t.Fatalf("%s row = %#v, want reason_code account_unresolved", name, row)
		}
	}
	if protected := want == "protected"; legacy["protected"] != protected || (cowork["state"] == "protected") != protected {
		t.Fatalf("claude_code = %#v, cowork = %#v, want protected %v", legacy, cowork, protected)
	}
}

// The Unix caller's uid is proven by the kernel but its account name can fail
// to resolve. An exclude_users entry that may be that name then claims no
// protection; an account with no entries keeps its rows, and root is decided by
// enrollment.root.
func TestOwnStatusUnixUnresolvedAccountNameClaimsNoProtection(t *testing.T) {
	for _, tc := range []struct {
		name, uid, account string
		exclude            []string
		want               string
	}{
		{"name entry, name unresolved", "5003", "", []string{"carol"}, "not confirmed"},
		{"other name entry, name unresolved", "5001", "", []string{"carol"}, "not confirmed"},
		{"uid entry, name unresolved", "5003", "", []string{"5003"}, "excluded"},
		{"name entry, name resolved", "5003", "carol", []string{"carol"}, "excluded"},
		{"other name entry, name resolved", "5001", "alice", []string{"carol"}, "protected"},
		{"no entries, name unresolved", "5003", "", nil, "protected"},
		{"root, name unresolved", "0", "", []string{"carol"}, "protected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := ownStatusExcludedFixture(t, tc.exclude, nil)
			answer := api.ownStatusAnswer(context.Background(), "uid", tc.uid, tc.account, "")
			if tc.want == "excluded" {
				requireExcludedAnswer(t, answer, "excluded_users_inspected")
				return
			}
			if tc.uid == "0" {
				if row := ownStatusRowFor(t, api, "uid", "0", "", "claudecode"); row["state"] == "excluded" || row["reason_code"] == "account_unresolved" {
					t.Fatalf("root row = %#v, want the root policy row", row)
				}
				return
			}
			requireUnresolvedOrState(t, answer, tc.want)
		})
	}
}
