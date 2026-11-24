// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gap0674WindowsForms are the spellings of folder only a Windows host has:
// the drive letter in each case, forward slashes, the \\?\ prefix, the 8.3
// short name (where the volume keeps short names) and a junction to it (a
// link a standard user may make, as the GAP-0674 replay does).
func gap0674WindowsForms(t *testing.T, folder string) []gap0674FolderForm {
	t.Helper()
	forms := []gap0674FolderForm{
		{"upper case", strings.ToUpper(folder)},
		{"lower case", strings.ToLower(folder)},
		{"forward slashes", filepath.ToSlash(folder)},
		{`\\?\`, `\\?\` + folder},
		{"trailing separator", folder + `\`},
	}
	junction := filepath.Join(t.TempDir(), "j-"+filepath.Base(folder))
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, folder).CombinedOutput(); err == nil {
		forms = append(forms, gap0674FolderForm{"junction", junction})
	} else {
		t.Errorf("no junction to %s: %v %s", folder, err, out)
	}
	out, err := exec.Command("cmd", "/c", "for", "%I", "in", "("+folder+")", "do", "@echo", "%~sI").Output()
	short := strings.TrimSpace(string(out))
	if _, statErr := os.Stat(short); err == nil && statErr == nil && !strings.EqualFold(short, folder) {
		forms = append(forms, gap0674FolderForm{"8.3", short})
	} else {
		t.Logf("no 8.3 form of %s (%q, %v): the volume keeps no short names", folder, short, err)
	}
	return forms
}
