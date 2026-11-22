// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

// rel-1-0-10 GAP-0907: an elevated Administrator is denied some account
// folders that LocalSystem reads (an account's .codex and
// .copilot\installed-plugins). Retire as Administrator then counted a
// healthy, converted profile as holding retire back and accepted
// --skip-profile for it: the skip was audited HIGH and recorded, and status
// as Administrator listed the converted account as not retired.

const (
	deniedCodexFile   = `C:\Users\dcw-std2\.codex\config.toml`
	deniedCopilotFile = `C:\Users\dcw-std2\.copilot\installed-plugins\defenseclaw\defenseclaw\hooks\hooks.json`
)

// deniedScan is the scan of a profile whose two files the caller was
// denied, through the account view the real scan uses.
func deniedScan(t *testing.T) windowsHookImageConfigScan {
	t.Helper()
	view := windowsHookImageAccountView(func(home, path string) (fs.FileInfo, []fs.DirEntry, error) {
		return nil, nil, fmt.Errorf("open %s: %w", path, fs.ErrPermission)
	})
	entries := []windowsHookImageConfigFile{
		{Path: deniedCodexFile, User: true, Home: `C:\Users\dcw-std2`, SID: skipTestSID},
		{Path: deniedCopilotFile, User: true, Home: `C:\Users\dcw-std2`, SID: skipTestSID},
	}
	_, _, unverified := expandWindowsHookImageConfigFiles(entries, nil, nil, view)
	if len(unverified) != 2 {
		t.Fatalf("unverified = %+v", unverified)
	}
	return windowsHookImageConfigScan{Named: map[string][]string{}, UserFiles: map[string]bool{}, FileSIDs: map[string]string{}, Unverified: unverified}
}

func TestHookImageRetireRefusesAnAdministratorSkipOfAProfileItWasOnlyDenied(t *testing.T) {
	s := newSkipFixture(t)
	scan := deniedScan(t)
	steps := s.skipSteps(skipTestSID)
	steps.Scan = func() windowsHookImageConfigScan { return scan }
	report := retireWindowsHookImages(steps)
	if report.OK || report.Reason != windowsHookImageRetireRefused || !strings.Contains(report.Error, "LocalSystem") ||
		!strings.Contains(report.Error, deniedCodexFile) || !strings.Contains(report.Error, "Nothing was changed") {
		t.Fatalf("an Administrator skip of a profile it was only denied = %+v, want refused (run as LocalSystem)", report)
	}
	if len(s.markers) != 0 || len(s.audits) != 0 || s.restarted != 0 || s.reconciled != 0 {
		t.Fatalf("a refused skip changed something: markers %v audits %d restarted %d reconciled %d", s.markers, len(s.audits), s.restarted, s.reconciled)
	}
}
