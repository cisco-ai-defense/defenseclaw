// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"path/filepath"
	"testing"
)

// A path that starts with a separator and names no drive is rooted on the
// drive of the working folder; it is not a path below the working folder. A
// shell command run from inside a skill folder that names /dev/null does not
// name that skill folder, and a rooted path to a skill folder without its drive
// letter still does.
func TestRootedPathWithoutADriveIsNotBelowTheWorkingFolder(t *testing.T) {
	home, _, held := skillTree(t)
	if got := placeIn("/dev/null", held); got != filepath.VolumeName(held)+`\dev\null` && got != filepath.VolumeName(held)+"/dev/null" {
		t.Errorf("placeIn(/dev/null) = %q, want it rooted on %q", got, filepath.VolumeName(held))
	}
	for name, command := range map[string]string{
		"quoted text":      `echo "/dev/null; ls"`,
		"quoted and":       `printf "/dev/null && find -name x"`,
		"function body":    `f() { cat /dev/null; }; echo ok`,
		"redirect target":  `echo ok > /dev/null`,
		"plain null path":  `echo /dev/null`,
		"parent of a root": `echo /../dev/null`,
	} {
		if refs := SkillFolderRefs("Bash", map[string]any{"command": command}, home, held); reaches(refs, held) {
			t.Errorf("%s: %q names the working skill folder: %+v", name, command, refs)
		}
	}
	// The protected twin: the skill folder spelled from the root of its drive.
	rooted := held[len(filepath.VolumeName(held)):]
	for name, command := range map[string]string{
		"read":       `type ` + rooted + `\SKILL.md`,
		"slash read": `cat ` + filepath.ToSlash(rooted) + `/SKILL.md`,
	} {
		if refs := SkillFolderRefs("Bash", map[string]any{"command": command}, home, filepath.Join(home, "proj")); !reaches(refs, held) {
			t.Errorf("%s: %q does not reach the skill folder: %+v", name, command, refs)
		}
	}
}
