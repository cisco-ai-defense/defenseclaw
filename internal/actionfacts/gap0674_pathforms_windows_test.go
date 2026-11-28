//go:build windows

package actionfacts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// credentialWalkPathForms are the forms of a folder's path the walk is tried
// with on Windows: as it is, with a trailing separator, with a dot segment,
// upper and lower case, forward slashes, the \\?\ prefix, and a junction to
// the folder (a link a standard user may make, as the GAP-0674 repro does).
func credentialWalkPathForms(t *testing.T, root string) []string {
	t.Helper()
	forms := []string{
		root,
		root + `\`,
		root + `\.`,
		strings.ToUpper(root),
		strings.ToLower(root),
		filepath.ToSlash(root),
		`\\?\` + root,
	}
	junction := filepath.Join(t.TempDir(), "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, root).CombinedOutput(); err == nil {
		forms = append(forms, junction)
	} else {
		t.Logf("no junction: %v %s", err, out)
	}
	if short := credentialWalkShortPath(root); short != "" && short != root {
		forms = append(forms, short)
	}
	return forms
}

// credentialWalkShortPath is the 8.3 form of a path, "" where it has none.
func credentialWalkShortPath(p string) string {
	// Only the parts of the temp folder's path that have a short name differ;
	// cmd's %~s expansion gives the form without a system call of our own.
	out, err := exec.Command("cmd", "/c", "for", "%I", "in", "("+p+")", "do", "@echo", "%~sI").Output()
	if err != nil {
		return ""
	}
	short := strings.TrimSpace(string(out))
	if _, err := os.Stat(short); err != nil {
		return ""
	}
	return short
}
