// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// rel-1-0-10 GAP-0794 review F4 (owner decision): retire waits for every
// enrolled account by default; an administrator may name, one by one, the
// profiles to skip (--skip-profile <SID>). Each skip is audited, listed in
// the result and recorded in the retire marker, and status and verify list
// the profile as not retired until it no longer names a launch folder. No
// blanket force, and a SID that is not an enrolled profile still blocking
// retire is refused with nothing changed.

const (
	skipTestSID   = "S-1-5-21-1-2-3-1018"
	skipTestOther = "S-1-5-21-1-2-3-1017"
)

type skipFixture struct {
	*retireFixture
	audits  []windowsHookImageSkippedProfile
	auditOK bool
	sids    map[string]string // account file (lower case) -> SID
}

func newSkipFixture(t *testing.T) *skipFixture {
	return &skipFixture{retireFixture: newRetireFixture(t), auditOK: true, sids: map[string]string{}}
}

func (s *skipFixture) skipSteps(skip ...string) windowsHookImageRetireSteps {
	steps := s.steps()
	scan := steps.Scan
	steps.Scan = func() windowsHookImageConfigScan {
		out := scan()
		out.FileSIDs = s.sids
		return out
	}
	steps.SkipProfiles = skip
	steps.Profiles = func() (map[string]windowsHookImageProfile, error) {
		return map[string]windowsHookImageProfile{
			skipTestSID:   {Account: `HOST\dcw-std2`, Home: `C:\Users\dcw-std2`},
			skipTestOther: {Account: `HOST\dcw-std1`, Home: `C:\Users\dcw-std1`},
		}, nil
	}
	steps.Actor = func() string { return `HOST\admin (S-1-5-21-1-2-3-500)` }
	steps.Audit = func(p windowsHookImageSkippedProfile) error {
		if !s.auditOK {
			return errors.New("gateway audit endpoint is unavailable")
		}
		s.audits = append(s.audits, p)
		return nil
	}
	steps.ReadMarker = func(path string) ([]byte, error) {
		node, ok := s.fs.get(path)
		if !ok {
			return nil, errors.New("not found")
		}
		return []byte(node.data), nil
	}
	return steps
}

func (s *skipFixture) accountFile(path, sid string) {
	if s.userFiles == nil {
		s.userFiles = map[string]bool{}
	}
	s.userFiles[strings.ToLower(path)] = true
	s.sids[strings.ToLower(path)] = sid
}

const skipTestFile = `C:\Users\dcw-std2\.copilot\hooks\defenseclaw-vscode.json`

func TestHookImageRetireSkipProfileRecordsAndAuditsTheSkip(t *testing.T) {
	s := newSkipFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(s.recorded["hook"])
	s.accountFile(skipTestFile, skipTestSID)
	s.named = []map[string][]string{{folder: {skipTestFile}}}
	report := retireWindowsHookImages(s.skipSteps(skipTestSID))
	if !report.OK || len(report.StillNamed) != 0 {
		t.Fatalf("retire with the blocking profile skipped = %+v", report)
	}
	if len(report.SkippedProfiles) != 1 || report.SkippedProfiles[0].SID != skipTestSID ||
		len(report.SkippedProfiles[0].Files) != 1 || report.SkippedProfiles[0].Files[0].File != skipTestFile ||
		report.SkippedProfiles[0].SkippedBy == "" || report.SkippedProfiles[0].SkippedAt == "" {
		t.Fatalf("skipped profiles = %+v", report.SkippedProfiles)
	}
	if len(s.audits) != 1 || s.audits[0].SID != skipTestSID || s.audits[0].SkippedBy != `HOST\admin (S-1-5-21-1-2-3-500)` ||
		len(s.audits[0].Files) != 1 {
		t.Fatalf("audits = %+v", s.audits)
	}
	node, ok := s.fs.get(report.Marker)
	if !ok {
		t.Fatal("no marker")
	}
	var marker windowsHookImageRetireMarker
	if err := json.Unmarshal([]byte(node.data), &marker); err != nil || len(marker.SkippedProfiles) != 1 ||
		marker.SkippedProfiles[0].SID != skipTestSID || marker.SkippedProfiles[0].Home != `C:\Users\dcw-std2` {
		t.Fatalf("marker %s: %v", node.data, err)
	}
	// A repeated retire keeps the recorded skip.
	again := retireWindowsHookImages(s.skipSteps(skipTestSID))
	node, _ = s.fs.get(report.Marker)
	if !again.OK || !strings.Contains(node.data, skipTestSID) {
		t.Fatalf("second retire = %+v, marker %s", again, node.data)
	}
}

func TestHookImageRetireSkipProfileRefusesWithNothingChanged(t *testing.T) {
	for _, tc := range []struct {
		name, sid, want string
	}{
		{"not a SID", "dcw-std2", "not a Windows SID"},
		{"not an enrolled profile", "S-1-5-21-9-9-9-1001", "not an enrolled profile"},
		{"enrolled but not blocking", skipTestOther, "does not hold retire back"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSkipFixture(t)
			folder, _ := winpath.EnterpriseHookImageDigest(s.recorded["hook"])
			s.accountFile(skipTestFile, skipTestSID)
			s.named = []map[string][]string{{folder: {skipTestFile}}}
			report := retireWindowsHookImages(s.skipSteps(tc.sid))
			if report.OK || report.Reason != windowsHookImageRetireRefused || !strings.Contains(report.Error, tc.want) ||
				!strings.Contains(report.Error, "Nothing was changed") {
				t.Fatalf("retire = %+v", report)
			}
			if len(s.markers) != 0 || s.restarted != 0 || s.reconciled != 0 || len(s.audits) != 0 {
				t.Fatalf("a refused skip changed something: markers %v restarted %d audits %v", s.markers, s.restarted, s.audits)
			}
		})
	}
}

// Only an account's own configs can be skipped: a machine file that still
// names a launch folder keeps retire pending whatever is skipped.
func TestHookImageRetireSkipProfileNeverSkipsAMachineFile(t *testing.T) {
	s := newSkipFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(s.recorded["hook"])
	machine := `C:\ProgramData\Cisco\DefenseClaw\hooks\opencode\enrollment.json`
	s.accountFile(skipTestFile, skipTestSID)
	s.named = []map[string][]string{{folder: {skipTestFile, machine}}}
	report := retireWindowsHookImages(s.skipSteps(skipTestSID))
	if report.OK || report.Reason != windowsHookImageRetirePending || len(report.StillNamed) != 1 || report.StillNamed[0].File != machine {
		t.Fatalf("retire = %+v", report)
	}
}

// The skip is recorded only with its audit row: a row the gateway did not
// take leaves the profile blocking.
func TestHookImageRetireSkipProfileWithoutAnAuditRowStaysPending(t *testing.T) {
	s := newSkipFixture(t)
	s.auditOK = false
	folder, _ := winpath.EnterpriseHookImageDigest(s.recorded["hook"])
	s.accountFile(skipTestFile, skipTestSID)
	s.named = []map[string][]string{{folder: {skipTestFile}}}
	report := retireWindowsHookImages(s.skipSteps(skipTestSID))
	if report.OK || report.Reason != windowsHookImageRetirePending || len(report.SkippedProfiles) != 0 ||
		len(report.StillNamed) != 1 || !strings.Contains(report.Error, "audit") {
		t.Fatalf("retire = %+v", report)
	}
	if node, _ := s.fs.get(report.Marker); node != nil && strings.Contains(node.data, skipTestSID) {
		t.Fatalf("an unaudited skip reached the marker: %s", node.data)
	}
}

// A profile the guardian converted while retire waited (it signed in) is
// not skipped: nothing to audit.
func TestHookImageRetireSkipProfileThatGotRewrittenIsNotSkipped(t *testing.T) {
	s := newSkipFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(s.recorded["hook"])
	s.accountFile(skipTestFile, skipTestSID)
	s.named = []map[string][]string{{folder: {skipTestFile}}, {}}
	report := retireWindowsHookImages(s.skipSteps(skipTestSID))
	if !report.OK || len(report.SkippedProfiles) != 0 || len(s.audits) != 0 {
		t.Fatalf("retire = %+v audits %v", report, s.audits)
	}
}

// Status and verify list a skipped profile as not retired until none of its
// recorded files names a launch folder (or can no longer be read to tell).
func TestHookImageSkippedProfilesNotRetired(t *testing.T) {
	launch := hookImageTestBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	marker, _ := json.Marshal(windowsHookImageRetireMarker{SchemaVersion: 1, SkippedProfiles: []windowsHookImageSkippedProfile{
		{SID: skipTestSID, Account: `HOST\dcw-std2`, Home: `C:\Users\dcw-std2`, SkippedBy: "HOST\\admin", SkippedAt: "2026-11-15T05:00:00Z",
			Files: []windowsHookImageNamedFile{{File: skipTestFile, Folder: "0123456789abcdef", Account: true}}},
		{SID: skipTestOther, Account: `HOST\dcw-std1`, Home: `C:\Users\dcw-std1`, SkippedBy: "HOST\\admin", SkippedAt: "2026-11-15T05:00:00Z",
			Files: []windowsHookImageNamedFile{{File: `C:\Users\dcw-std1\.hermes\config.yaml`, Folder: "0123456789abcdef", Account: true}}},
	}})
	read := func(file windowsHookImageConfigFile) ([]byte, error) {
		if !file.User || file.Home == "" {
			t.Fatalf("a skipped profile file must be read as an account file below its home: %+v", file)
		}
		if file.Path == skipTestFile {
			return []byte(`{"command":"` + strings.ReplaceAll(launch, `\`, `\\`) + `"}`), nil
		}
		return []byte(`hooks: {}`), nil
	}
	lines := windowsHookImageSkippedProfilesNotRetired(marker, hookImageTestBin, read)
	if len(lines) != 1 || !strings.Contains(lines[0], skipTestSID) || !strings.Contains(lines[0], skipTestFile) ||
		!strings.Contains(lines[0], "not retired") || strings.Contains(lines[0], skipTestOther) {
		t.Fatalf("not retired = %v", lines)
	}
	unreadable := windowsHookImageSkippedProfilesNotRetired(marker, hookImageTestBin, func(windowsHookImageConfigFile) ([]byte, error) {
		return nil, errors.New("access denied")
	})
	if len(unreadable) != 2 {
		t.Fatalf("unreadable files must keep both profiles listed: %v", unreadable)
	}
	if got := windowsHookImageSkippedProfilesNotRetired([]byte(`{"schema_version":1,"retired_at":"x"}`), hookImageTestBin, read); len(got) != 0 {
		t.Fatalf("a marker without skips lists %v", got)
	}
}

func encodePowerShellForTest(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 0, 2*len(units))
	for _, u := range units {
		raw = append(raw, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// The -EncodedCommand spellings PowerShell accepts (-e, -ec, -enc...,
// --EncodedCommand, /EncodedCommand) are read; a value that cannot be
// decoded counts as unknown, not as naming nothing.
func TestHookImageScanEncodedCommandSpellingsAndUnknownValues(t *testing.T) {
	launch := hookImageTestBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	script := encodePowerShellForTest("& '" + launch + "' hook --connector copilot")
	for _, flag := range []string{"-e", "-ec", "-EC", "-enc", "-EncodedCommand", "--EncodedCommand", "/EncodedCommand", "/ec"} {
		body := []byte(`{"command":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile ` + flag + ` ` + script + `"}`)
		if got := strings.Join(windowsHookImageFoldersNamedIn(body, hookImageTestBin), ","); got != "0123456789abcdef" {
			t.Errorf("%s: folders = %q", flag, got)
		}
	}
	for name, body := range map[string]string{
		"invalid base64": `powershell.exe -NoProfile -ec !!!notbase64`,
		"odd length":     `pwsh -EncodedCommand ` + base64.StdEncoding.EncodeToString([]byte("abc")),
		"too large":      `powershell.exe -ec ` + strings.Repeat("QUFB", windowsHookImageEncodedScriptLimit/4+1),
	} {
		if got := windowsHookImageFoldersNamedIn([]byte(body), hookImageTestBin); strings.Join(got, ",") != windowsHookImageUnknownFolder {
			t.Errorf("%s: folders = %v, want %s", name, got, windowsHookImageUnknownFolder)
		}
	}
	// Not a PowerShell command line, or another switch: nothing.
	for _, body := range []string{`bash -e /usr/bin/x`, `powershell.exe -ExecutionPolicy Bypass -File x.ps1`, `powershell.exe -EncodedArguments QUFB`} {
		if got := windowsHookImageFoldersNamedIn([]byte(body), hookImageTestBin); len(got) != 0 {
			t.Errorf("%q: folders = %v", body, got)
		}
	}
	// An unknown machine file makes the scan incomplete; an unknown account
	// file holds retire back like a named launch folder.
	unknown := []byte(`powershell.exe -ec !!!`)
	scan := scanWindowsHookImageConfigFiles([]windowsHookImageConfigFile{
		{Path: `C:\ProgramData\m.json`}, {Path: `C:\Users\u\a.json`, User: true, Home: `C:\Users\u`, SID: skipTestSID},
	}, hookImageTestBin, func(windowsHookImageConfigFile) ([]byte, error) { return unknown, nil })
	if len(scan.Incomplete) != 1 || !strings.HasPrefix(scan.Incomplete[0], `C:\ProgramData\m.json`) ||
		strings.Join(scan.Named[windowsHookImageUnknownFolder], ",") != `C:\Users\u\a.json` ||
		scan.FileSIDs[strings.ToLower(`C:\Users\u\a.json`)] != skipTestSID {
		t.Fatalf("scan = %+v", scan)
	}
}

// Every PowerShell bridge DefenseClaw renders is read in full: it names its
// own launch folder, and never "unknown" (a false unknown in a machine file
// would keep retire pending and prune idle for good).
func TestHookImageScanReadsEveryRenderedBridge(t *testing.T) {
	launch := hookImageTestBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	commands := map[string]string{
		"codex managed":          connector.WindowsCodexManagedHookCommand(launch),
		"codex standalone":       connector.WindowsCodexStandaloneManagedHookCommand(launch, "PreToolUse", "v1"),
		"copilot vscode":         connector.CopilotVSCodeLocalManagedHookCommand("windows", launch, "PreToolUse"),
		"copilot vscode prior":   connector.CopilotVSCodeLocalPriorReleaseHookCommand("windows", launch, "PreToolUse"),
		"copilot vscode guarded": connector.CopilotVSCodeLocalGuardedPriorReleaseHookCommand("windows", launch, "PreToolUse"),
	}
	for name, command := range commands {
		if command == "" {
			continue
		}
		body, _ := json.Marshal(map[string]string{"command": command})
		for _, text := range [][]byte{[]byte(command), body} {
			if got := strings.Join(windowsHookImageFoldersNamedIn(text, hookImageTestBin), ","); got != "0123456789abcdef" {
				t.Errorf("%s: folders = %q", name, got)
			}
		}
	}
}
