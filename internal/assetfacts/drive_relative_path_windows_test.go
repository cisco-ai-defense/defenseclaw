// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// junction makes link a folder junction to target (it needs no privilege).
func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction here: %v %s", err, out)
	}
}

// A path with a drive and no separator after it (C:link\SKILL.md) is relative
// to the working folder of that drive. On the drive of the working folder it
// is below the working folder, so a link there that leads into a skill folder
// reaches it as the same name without the drive does. A path on another drive
// has a working folder the hook event does not hold: it cannot be placed, and
// the call is recorded as one whose links are unproven.
func TestDriveRelativePathIsBelowTheWorkingFolderOfItsDrive(t *testing.T) {
	home, _, held := skillTree(t)
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "notes.txt"), []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	junction(t, filepath.Join(proj, "lnk-held"), held)
	vol := filepath.VolumeName(proj)
	otherVol := "D:"
	if strings.EqualFold(vol, otherVol) {
		otherVol = "E:"
	}
	noted := 0
	UnprovenLinkNote = func() { noted++ }
	t.Cleanup(func() { UnprovenLinkNote = nil })

	for in, want := range map[string]string{
		vol + `lnk-held\SKILL.md`:      proj + `\lnk-held\SKILL.md`,
		strings.ToLower(vol) + `.\lnk`: proj + `\.\lnk`,
		vol + `..\x`:                   proj + `\..\x`,
		vol:                            proj,
		`\dev\null`:                    vol + `\dev\null`,
		`plain\name`:                   proj + `\plain\name`,
		proj + `\already\absolute`:     proj + `\already\absolute`,
	} {
		if got := placeIn(in, proj); got != want {
			t.Errorf("placeIn(%q) = %q, want %q", in, got, want)
		}
	}
	if noted != 0 {
		t.Fatalf("a path of the drive of the working folder was recorded as unproven %d times", noted)
	}
	if got := placeIn(otherVol+`x\y`, proj); got != otherVol+`x\y` || noted != 1 {
		t.Errorf("a path on another drive: placeIn = %q, recorded %d times; want it as written, recorded once", got, noted)
	}

	for name, tc := range map[string]struct {
		tool, key string
		value     any
	}{
		"read":          {"Read", "file_path", vol + `lnk-held\SKILL.md`},
		"read dot":      {"Read", "file_path", vol + `.\lnk-held\SKILL.md`},
		"read lower":    {"Read", "file_path", strings.ToLower(vol) + `lnk-held\SKILL.md`},
		"grep":          {"Grep", "path", vol + `lnk-held`},
		"glob":          {"Glob", "path", vol + `lnk-held`},
		"glob dot":      {"Glob", "path", vol + `.\lnk-held`},
		"shell reader":  {"Bash", "command", `type ` + vol + `lnk-held\SKILL.md`},
		"shell listing": {"Bash", "command", `dir ` + vol + `lnk-held`},
		"shell argv":    {"Bash", "command", []any{"cmd", "/c", "dir", vol + `lnk-held`}},
	} {
		noted = 0
		if refs := SkillFolderRefs(tc.tool, map[string]any{tc.key: tc.value}, home, proj); !reaches(refs, held) {
			t.Errorf("%s: %s %s=%q does not reach the held skill folder: %+v", name, tc.tool, tc.key, tc.value, refs)
		}
		if noted != 0 {
			t.Errorf("%s: a path of the drive of the working folder was recorded as unproven", name)
		}
	}
	for name, tc := range map[string]struct {
		tool, key string
		value     any
	}{
		"bare same drive": {"Bash", "command", `dir ` + vol + `notes.txt`},
		"no drive":        {"Bash", "command", `dir notes.txt`},
		"no drive argv":   {"Bash", "command", []any{"cmd", "/c", "dir", "notes.txt"}},
		"ordinary file":   {"Read", "file_path", vol + `notes.txt`},
		"working folder":  {"Grep", "path", vol + `.`},
		"ordinary reader": {"Bash", "command", `type ` + vol + `notes.txt`},
	} {
		noted = 0
		if refs := SkillFolderRefs(tc.tool, map[string]any{tc.key: tc.value}, home, proj); reaches(refs, held) {
			t.Errorf("twin %s: %s %s=%q reaches the held skill folder: %+v", name, tc.tool, tc.key, tc.value, refs)
		}
		if noted != 0 {
			t.Errorf("twin %s: recorded as unproven", name)
		}
	}
	for name, tc := range map[string]struct {
		tool, key string
		value     any
	}{
		"read":         {"Read", "file_path", otherVol + `lnk-held\SKILL.md`},
		"grep":         {"Grep", "path", otherVol + `lnk-held`},
		"reader":       {"Bash", "command", `type ` + otherVol + `lnk-held\SKILL.md`},
		"bare listing": {"Bash", "command", `dir ` + otherVol + `lnk-held`},
		"bare shell":   {"Bash", "command", `cmd /c dir ` + otherVol + `lnk-held`},
		"bare argv":    {"Bash", "command", []any{"cmd", "/c", "dir", otherVol + `lnk-held`}},
	} {
		noted = 0
		SkillFolderRefs(tc.tool, map[string]any{tc.key: tc.value}, home, proj)
		if noted == 0 {
			t.Errorf("other drive %s: %s %s=%q was not recorded as unproven", name, tc.tool, tc.key, tc.value)
		}
	}
}
