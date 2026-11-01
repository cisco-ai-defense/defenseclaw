// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"golang.org/x/sys/windows"
)

// GAP-0856: a standalone rollback whose per-user runtime cleanup failed goes
// on and reports each folder the rolled back change created. That leftover
// is not one of a failed first install, and /ensure then /uninstall (the
// first-install remedy) would remove the deployment the rollback put back:
// the warning says the restored release does not use the folder and how to
// remove it. Other leftovers keep their remedy.
func TestWindowsEnterpriseRollbackLeftoverOfACreatedFolder(t *testing.T) {
	created := `C:\Users\carol\.defenseclaw (account S-1-5-21-1-2-3-1020), if it exists: a per-user DefenseClaw folder this change created; the rollback could not remove it (inspect user home: access denied)`
	raw, err := json.Marshal([]string{created, "bob (S-1-5-21-1-2-3-1019) [codex]: DefenseClaw's agent registrations, because the account is not signed in"})
	if err != nil {
		t.Fatal(err)
	}
	warnings := windowsEnterpriseRollbackLeftoverWarnings(raw)
	if len(warnings) != 2 {
		t.Fatalf("warnings = %+v", warnings)
	}
	if warnings[0].Code != "rollback_leftover" || !strings.HasPrefix(warnings[0].Message, "the rollback left "+created) ||
		!strings.Contains(warnings[0].Message, "the restored release does not use that folder") ||
		strings.Contains(warnings[0].Message, "/uninstall") || strings.Contains(warnings[0].Message, "failed first install") {
		t.Fatalf("created-folder leftover = %q", warnings[0].Message)
	}
	if !strings.Contains(warnings[1].Message, "the rollback of the failed first install could not remove bob") ||
		!strings.Contains(warnings[1].Message, "/ensure and then /uninstall") {
		t.Fatalf("first-install leftover = %q", warnings[1].Message)
	}
}

func TestWindowsEnterpriseNativeOTLPRollbackLeftoverKeepsRestoredRelease(t *testing.T) {
	path := `C:\Users\dcw-std2\.codex\config.toml`
	leftover := "native OTLP user rollback: " + path + ": preimage could not be captured"
	raw, err := json.Marshal([]string{leftover})
	if err != nil {
		t.Fatal(err)
	}
	warnings := windowsEnterpriseRollbackLeftoverWarnings(raw)
	if len(warnings) != 1 || warnings[0].Code != "rollback_leftover" {
		t.Fatalf("warnings = %+v", warnings)
	}
	message := warnings[0].Message
	for _, want := range []string{
		"the rollback could not restore " + path + ": preimage could not be captured",
		"the restored release is running",
		"inspect that link or its permissions and restore it by hand",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("warning %q does not contain %q", message, want)
		}
	}
	if strings.Contains(message, "/uninstall") || strings.Contains(message, "failed first install") {
		t.Errorf("native OTLP warning recommends removing the restored deployment: %q", message)
	}
}

// GAP-0847: the targets a failed undo leaves without a hook are named: each
// enabled target published before the apply that the targets published now
// do not enroll, matched by SID and connector. A disabled row had no hook to
// lose.
func TestWindowsHotConfigDroppedTargetsNamesWhoLostAHook(t *testing.T) {
	off := false
	before := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{User: "alice", SID: "S-1-5-21-1-2-3-1001", Connector: "claudecode"},
		{User: "bob", SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode"},
		{User: "bob", SID: "S-1-5-21-1-2-3-1002", Connector: "codex"},
		{SID: "S-1-5-21-1-2-3-1003", Connector: "codex"},
		{User: "dave", SID: "S-1-5-21-1-2-3-1004", Connector: "codex", Enabled: &off},
	}}
	now := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{User: "alice", SID: "s-1-5-21-1-2-3-1001", Connector: "ClaudeCode"},
		{User: "bob", SID: "S-1-5-21-1-2-3-1002", Connector: "codex", Enabled: &off},
	}}
	got := strings.Join(windowsHotConfigTargetLabels(windowsHotConfigDroppedTargets(before, now)), ", ")
	want := "bob (S-1-5-21-1-2-3-1002) claudecode, bob (S-1-5-21-1-2-3-1002) codex, an account (S-1-5-21-1-2-3-1003) codex"
	if got != want {
		t.Fatalf("dropped = %q, want %q", got, want)
	}
}

// GAP-2571: a dropped target the enumerator published with its SID only
// (the targets.yaml rows real Windows writes) is named DOMAIN\user (SID),
// as the other Windows notices do (GAP-2290); "an account (SID)" is left
// for a SID that does not resolve.
func TestWindowsHotConfigTargetLabelsResolveASIDOnlyTarget(t *testing.T) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("token user: %v", err)
	}
	sid := tokenUser.User.Sid.String()
	// GAP-2630: the label is the SID's own DOMAIN\account. user.Current
	// cannot be the oracle: as LocalSystem on a domain-joined host it names
	// the machine account (DOMAIN\HOST$) while the SID resolves to
	// NT AUTHORITY\SYSTEM, so read the account from the SID itself.
	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil || account == "" {
		t.Fatalf("lookup account of the token SID: %v", err)
	}
	name := account
	if domain != "" {
		name = domain + `\` + account
	}
	got := strings.Join(windowsHotConfigTargetLabels([]enterprisehooks.ManifestTarget{
		{SID: sid, UserHome: `C:\Users\someone`, Connector: "opencode"},
		{SID: "S-1-5-21-1-2-3-1003", Connector: "codex"},
		{User: "bob", SID: "S-1-5-21-1-2-3-1002", Connector: "codex"},
	}), ", ")
	want := name + " (" + sid + ") opencode, an account (S-1-5-21-1-2-3-1003) codex, bob (S-1-5-21-1-2-3-1002) codex"
	if !strings.EqualFold(got, want) {
		t.Fatalf("labels = %q, want %q", got, want)
	}
	if strings.Contains(strings.SplitN(got, ",", 2)[0], "an account") {
		t.Fatalf("a resolvable SID is still named as an account: %q", got)
	}
}
