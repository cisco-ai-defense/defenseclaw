//go:build !windows

package actionfacts

import (
	"os"
	"path/filepath"
	"testing"
)

// credentialWalkPathForms are the forms of a folder's path the walk is tried
// with: as it is, with a trailing separator, with a dot segment, and through
// a symbolic link to it.
func credentialWalkPathForms(t *testing.T, root string) []string {
	t.Helper()
	link := filepath.Join(t.TempDir(), "link")
	forms := []string{root, root + string(filepath.Separator), filepath.Join(root, ".") + string(filepath.Separator) + ".", root + "/./"}
	if err := os.Symlink(root, link); err == nil {
		forms = append(forms, link)
	}
	return forms
}
