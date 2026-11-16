// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const coworkHealth = `{"connectors":[{"name":"codex","surfaces":{"cowork":{"requests":9}}},
{"name":"claudecode","state":"running","surfaces":{"cowork":{"requests":12,"last_activity_at":"2026-11-03T13:16:05.123Z"}}}]}`

func TestBuildCoworkCoveredWithPerAccountLastEvent(t *testing.T) {
	at := time.Date(2026, 11, 3, 13, 10, 0, 0, time.UTC)
	state := BuildCowork(CoworkInputs{
		Enabled: true, MachinePolicy: true, HooksInstalled: HooksInstalledAll, ManagedHooksOnly: "enforce",
		Health:   []byte(coworkHealth),
		Enrolled: []CoworkEnrolledAccount{{Account: "alice", IDs: []string{"501"}}, {Account: "bob", IDs: []string{"502"}}},
		Events: []CoworkAccountEvent{
			{UserID: "501", UserName: "alice", At: at},
			{UserID: "501", UserName: "alice", At: at.Add(-time.Hour)},
			{UserID: "777", UserName: "carol", At: at.Add(time.Minute)}, // not enrolled, still covered by machine policy
		},
	})
	if !state.Configured || state.Reason != "" || state.Requests != 12 || state.LastEventAt != "2026-11-03T13:16:05Z" || !state.AccountsKnown {
		t.Fatalf("state = %+v", state)
	}
	want := []CoworkAccount{{Account: "alice", LastEventAt: "2026-11-03T13:10:00Z"}, {Account: "bob"}, {Account: "carol", LastEventAt: "2026-11-03T13:11:00Z"}}
	if len(state.Accounts) != len(want) {
		t.Fatalf("accounts = %+v", state.Accounts)
	}
	for i := range want {
		if state.Accounts[i] != want[i] {
			t.Fatalf("accounts = %+v, want %+v", state.Accounts, want)
		}
	}
	text := strings.Join(CoworkLines(state), "\n")
	for _, part := range []string{"cowork: configured (DefenseClaw's Claude Code machine policy hooks are in place); 12 hook call(s) reported themselves as Cowork since the gateway started, last 2026-11-03T13:16:05Z; managed_hooks_only=enforce",
		"cowork bob: last call reported as Cowork never", "cowork alice: last call reported as Cowork 2026-11-03T13:10:00Z"} {
		if !strings.Contains(text, part) {
			t.Fatalf("text %q lacks %q", text, part)
		}
	}
	if configured := CoworkLines(state)[0]; strings.Contains(configured, "Cowork loads") {
		t.Fatalf("configured line %q still claims Cowork loads the hooks", configured)
	}
}

func TestBuildCoworkNotCoveredAndUnknownAccounts(t *testing.T) {
	for _, tc := range []struct {
		in   CoworkInputs
		want string
	}{
		{CoworkInputs{Enabled: false}, CoworkReasonConnectorDisabled},
		{CoworkInputs{Enabled: true, MachinePolicy: true, HooksInstalled: HooksInstalledNone}, CoworkReasonMachinePolicyUnset},
		{CoworkInputs{Enabled: true, MachinePolicy: false, HooksInstalled: HooksInstalledAll}, CoworkReasonMachinePolicyUnset},
	} {
		tc.in.EventsErr = errors.New("busy")
		state := BuildCowork(tc.in)
		if state.Configured || state.Reason != tc.want || state.AccountsKnown || len(state.Accounts) != 0 || state.Requests != 0 {
			t.Fatalf("BuildCowork(%+v) = %+v", tc.in, state)
		}
		if text := strings.Join(CoworkLines(state), "\n"); !strings.Contains(text, "not configured") || !strings.Contains(text, "unknown") ||
			!strings.Contains(text, "no hook call has reported itself as Cowork yet") {
			t.Fatalf("text = %q", text)
		}
	}
	// Configured with no call counted yet says so, without a fixed caveat
	// (cowork-1-0-8 GAP-0032).
	if state := BuildCowork(CoworkInputs{Enabled: true, MachinePolicy: true, HooksInstalled: HooksInstalledAll, ManagedHooksOnly: "preserve"}); CoworkLines(state)[0] !=
		"cowork: configured (DefenseClaw's Claude Code machine policy hooks are in place); no hook call has reported itself as Cowork yet (counted since the gateway started); managed_hooks_only=preserve (Cowork plugin hooks may run too)" {
		t.Fatalf("preserve line = %q", CoworkLines(state)[0])
	}
}

func TestParseCoworkHealthIgnoresOtherConnectorsAndBadBodies(t *testing.T) {
	for _, body := range []string{"", "not json", `{"connectors":[{"name":"claudecode"}]}`, `{"connectors":[{"name":"codex","surfaces":{"cowork":{"requests":3}}}]}`} {
		if requests, last := ParseCoworkHealth([]byte(body)); requests != 0 || last != "" {
			t.Fatalf("ParseCoworkHealth(%q) = %d %q", body, requests, last)
		}
	}
}

func TestBuildCoworkReportsTheRefusedDesktopSurface(t *testing.T) {
	state := BuildCowork(CoworkInputs{Enabled: true, MachinePolicy: true, HooksInstalled: HooksInstalledAll, DesktopSurfaceRefused: true})
	if state.Configured || state.Reason != CoworkReasonDesktopRefused || !strings.Contains(CoworkLines(state)[0], "unverified_versions: refuse") {
		t.Fatalf("refused desktop surface = %+v", state)
	}
}

func TestBuildCoworkSaysWhenAccountsAreCut(t *testing.T) {
	var enrolled []CoworkEnrolledAccount
	for i := range CoworkAccountsMax + 1 {
		enrolled = append(enrolled, CoworkEnrolledAccount{Account: fmt.Sprintf("user%03d", i)})
	}
	state := BuildCowork(CoworkInputs{Enabled: true, Enrolled: enrolled})
	if !state.AccountsTruncated || len(state.Accounts) != CoworkAccountsMax ||
		!strings.Contains(strings.Join(CoworkLines(state), "\n"), "more accounts than listed") {
		t.Fatalf("over the account cap = truncated %v, %d accounts", state.AccountsTruncated, len(state.Accounts))
	}
	state = BuildCowork(CoworkInputs{Enabled: true, Enrolled: enrolled[:2], EventsTruncated: true})
	if !state.AccountsTruncated || len(state.Accounts) != 2 {
		t.Fatalf("lookup at its row bound = %+v", state)
	}
	if state := BuildCowork(CoworkInputs{Enabled: true, Enrolled: enrolled[:2]}); state.AccountsTruncated {
		t.Fatalf("under both caps = %+v", state)
	}
}

// A store that answered with no enrolled account and no Cowork row says so
// (cowork-1-0-8 GAP-0025: the Linux host lists no account, its claudecode
// coverage is machine policy).
func TestCoworkLinesSayWhenTheStoreHasNoAccount(t *testing.T) {
	state := BuildCowork(CoworkInputs{Enabled: true, MachinePolicy: true, HooksInstalled: HooksInstalledAll})
	lines := CoworkLines(state)
	if !state.AccountsKnown || len(state.Accounts) != 0 || len(lines) != 2 ||
		lines[1] != "  cowork per account: none (no enrolled account, and no hook call in the audit store reported itself as Cowork)" {
		t.Fatalf("state = %+v, lines = %q", state, lines)
	}
}
