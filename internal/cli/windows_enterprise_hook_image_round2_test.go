// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/base64"
	"io/fs"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// turev #6: a file the scan could not read can be readable on the next
// poll (an account's agent held it open), so retire keeps polling while one
// is left, as it does for a file that names a launch folder.
func TestHookImageRetireWaitsForAnUnverifiedAccountFile(t *testing.T) {
	r := newRetireFixture(t)
	steps := r.steps()
	steps.Scan = func() windowsHookImageConfigScan {
		r.scans++
		scan := windowsHookImageConfigScan{Named: map[string][]string{}}
		if r.scans <= 2 {
			scan.Unverified = []windowsHookImageUnverifiedFile{{
				File: windowsHookImageConfigFile{Path: `C:\Users\u\.codex\config.toml`, User: true, Home: `C:\Users\u`, SID: skipTestSID},
				Err:  "The process cannot access the file because it is being used by another process.",
			}}
		}
		return scan
	}
	report := retireWindowsHookImages(steps)
	if !report.OK || r.scans < 3 {
		t.Fatalf("retire stopped polling over an unverified file (scans %d): %+v", r.scans, report)
	}
}

// rel-1-0-10 GAP-0886: an account path whose open does not answer (an oplock
// the account holds on its own agent config) must not keep retire, which
// holds lifecycle.lock, waiting: the view is bounded and the file is
// unverified.
func TestHookImageAccountViewIsBounded(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	view := windowsHookImageAccountView(func(home, path string) (fs.FileInfo, []fs.DirEntry, error) {
		<-block
		return nil, nil, fs.ErrNotExist
	})
	type result struct {
		files      []windowsHookImageConfigFile
		unverified []windowsHookImageUnverifiedFile
	}
	done := make(chan result, 1)
	go func() {
		files, _, unverified := expandWindowsHookImageConfigFiles([]windowsHookImageConfigFile{
			{Path: `C:\Users\u\.codex\config.toml`, User: true, Home: `C:\Users\u`, SID: skipTestSID},
		}, nil, nil, view)
		done <- result{files, unverified}
	}()
	select {
	case got := <-done:
		if len(got.files) != 0 || len(got.unverified) != 1 || !strings.Contains(got.unverified[0].Err, "did not answer") {
			t.Fatalf("a view that does not answer: files %+v, unverified %+v", got.files, got.unverified)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("expanding an account path whose open does not answer hung (GAP-0886)")
	}
}

// GAP-0886: a vendor folder element a standard user made can be held the
// same way; the inspection and the listing are bounded too.
func TestHookImageVendorListingIsBounded(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	vfs := windowsHookImageVendorFS{
		Inspect: func(root, path string) (winpath.BelowInfo, error) {
			<-block
			return winpath.BelowInfo{}, fs.ErrNotExist
		},
		List: func(root, path string) ([]fs.DirEntry, error) {
			<-block
			return nil, fs.ErrNotExist
		},
	}
	done := make(chan struct{})
	go func() {
		windowsHookImageVendorFiles(`C:\ProgramData`, `C:\ProgramData\Cursor`, 1, vfs)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("listing a vendor folder whose elements do not answer hung (GAP-0886)")
	}
}

// turev #7: PowerShell reads an en dash, em dash or horizontal bar as the
// switch hyphen, and takes -EncodedCommand:<value>.
func TestHookImageFoldersNamedInDashAndColonForms(t *testing.T) {
	const folder = "0123456789abcdef"
	script := "& '" + hookImageTestBin + `\hooks\` + folder + `\defenseclaw-hook.exe' hook --connector copilot`
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 0, 2*len(units))
	for _, unit := range units {
		raw = append(raw, byte(unit), byte(unit>>8))
	}
	value := base64.StdEncoding.EncodeToString(raw)
	for _, line := range []string{
		"powershell.exe -NoProfile \u2013EncodedCommand " + value,
		"pwsh \u2014ec " + value,
		"powershell \u2015e " + value,
		"powershell.exe -NoProfile -EncodedCommand:" + value,
		"pwsh /ec:" + value,
	} {
		if got := windowsHookImageFoldersNamedIn([]byte(`{"command":"`+line+`"}`), hookImageTestBin); len(got) != 1 || got[0] != folder {
			t.Errorf("%q: folders named = %v, want [%s]", line[:24], got, folder)
		}
	}
}
