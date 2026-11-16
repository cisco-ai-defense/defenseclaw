// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// cowork-1-0-8 GAP-0057: a managed Windows status and verify name each
// enrolled account's Claude Desktop engine build and its Authenticode trust,
// in text and JSON, as Linux and macOS do (GAP-0031).
func TestWindowsCoworkDesktopStateNamesEachEnrolledAccountsEngineTrust(t *testing.T) {
	const aliceSID, bobSID, carolSID = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1003"
	var asked []string
	folders := func(sid string) ([]enterprisehooks.ClaudeDesktopFolder, error) {
		asked = append(asked, sid)
		switch sid {
		case aliceSID:
			return []enterprisehooks.ClaudeDesktopFolder{
				{Deployment: "3p", Path: `C:\Users\alice\AppData\Local\Claude-3p`, EngineVersion: "2.1.317",
					EnginePath: `C:\Users\alice\AppData\Local\Claude-3p\claude-code\2.1.317\b\claude.exe`},
				{Deployment: "1p", Path: `C:\Users\alice\AppData\Roaming\Claude`, EngineVersion: "2.1.318",
					EnginePath: `C:\Users\alice\AppData\Roaming\Claude\claude-code\2.1.318`, Unverified: "claude.exe is not signed"},
				{Deployment: "1p", Path: `C:\Users\alice\AppData\Local\Claude-Data\claude_x`},
			}, nil
		case bobSID:
			return nil, errors.New("no signed-in session")
		}
		return nil, nil
	}
	accounts := []enterprisestatus.EnrollmentAccount{
		{Account: `CORP\bob`, SID: bobSID}, {Account: `CORP\alice`, SID: aliceSID}, {Account: `CORP\carol`, SID: carolSID},
		{Account: `CORP\dave`},
	}
	state := windowsCoworkDesktopState(accounts, folders)
	if !state.AccountsKnown || len(state.Accounts) != 4 || state.Trusted != 1 || state.Untrusted != 1 || state.NotFound != 1 || state.Unsigned != 0 {
		t.Fatalf("state = %+v", state)
	}
	if len(asked) != 3 {
		t.Fatalf("checked %v, want the three accounts with a SID", asked)
	}
	alice := state.Accounts[0]
	if alice.Account != `CORP\alice` || len(alice.Installs) != 3 || alice.Installs[0].Trust != enterprisestatus.CoworkEngineTrusted ||
		alice.Installs[1].Trust != enterprisestatus.CoworkEngineUntrusted || alice.Installs[2].Trust != enterprisestatus.CoworkEngineNotFound ||
		alice.Installs[2].EnginePath != "" {
		t.Fatalf("alice = %+v", alice)
	}
	if bob := state.Accounts[1]; len(bob.Installs) != 0 || bob.Reason != "no signed-in session" {
		t.Fatalf("bob = %+v", bob)
	}
	if dave := state.Accounts[3]; dave.Reason == "" || len(dave.Installs) != 0 {
		t.Fatalf("dave = %+v", dave)
	}
	text := strings.Join(enterprisestatus.CoworkLines(&enterprisestatus.CoworkState{Configured: true, AccountsKnown: true, ClaudeDesktop: state}), "\n")
	for _, want := range []string{
		`cowork CORP\alice: Claude Desktop 3p (C:\Users\alice\AppData\Local\Claude-3p), engine 2.1.317 trusted`,
		`cowork CORP\alice: Claude Desktop 1p (C:\Users\alice\AppData\Roaming\Claude), engine 2.1.318 untrusted (claude.exe is not signed)`,
		`cowork CORP\alice: Claude Desktop 1p (C:\Users\alice\AppData\Local\Claude-Data\claude_x), no engine build`,
		`cowork CORP\bob: Claude Desktop not checked (no signed-in session)`,
		`cowork CORP\carol: no Claude Desktop data folder`,
		`cowork CORP\dave: Claude Desktop not checked (the enrollment row names no SID)`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
}
