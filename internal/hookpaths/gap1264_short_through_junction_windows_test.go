// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// rel-1-0-10:GAP-1264 (CHK-RF-WINPATH-R2 Q4, P5): an 8.3 name whose path
// passes through a junction (a short component below one, or a junction
// spelled by its own short name, as C:\DOCUME~1) was no longer expanded
// once the expander read only prefixes the share walk read as spelled, so
// a benign write to it became an unproven dynamic argument where rel gave
// no finding. Each 8.3 component is now expanded from the gated read of its
// parent folder, keeping the spelled prefix, as GetLongPathName of the name
// expanded it at rel.
func TestGAP1264ShortNameThroughJunctionIsExpanded(t *testing.T) {
	short := func(t *testing.T, path string) string {
		t.Helper()
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n, err := windows.GetShortPathName(name, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 || n >= uint32(len(buf)) {
			t.Skipf("8.3 aliases unavailable on this volume: %v", err)
		}
		value := windows.UTF16ToString(buf[:n])
		if !strings.Contains(value, "~") {
			t.Skip("8.3 aliases disabled on this volume")
		}
		return value
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	cwd := filepath.Join(base, "project")
	target := filepath.Join(base, "Long Folder Name")
	for _, dir := range []string{home, cwd, filepath.Join(target, "Another Long Name")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(target, "Another Long Name", "file with long name.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	junction := func(t *testing.T, link string) {
		t.Helper()
		if _, err := os.Lstat(link); err == nil {
			return
		}
		if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Fatalf("create junction: %v: %s", err, out)
		}
	}
	rows := []struct {
		id, link, below string
		// newName is a name below the long path that does not exist yet:
		// it has no 8.3 alias and is kept as spelled.
		newName string
	}{
		{"below-junction", "jn", `Another Long Name\file with long name.txt`, ""},
		{"below-junction-dir", "jn", `Another Long Name`, ""},
		{"below-junction-new-name", "jn", `Another Long Name`, "new-file.txt"},
		{"junction-own-short-name", "Junction Long Name", `Another Long Name\file with long name.txt`, ""},
	}
	for _, r := range rows {
		t.Run(r.id, func(t *testing.T) {
			link := filepath.Join(base, r.link)
			junction(t, link)
			long := filepath.Join(link, r.below)
			value := short(t, long)
			if r.newName != "" {
				value += `\` + r.newName
				long = filepath.Join(long, r.newName)
			}
			got, ok := actionWindowsExpandShortPath(value)
			t.Logf("GAP1264ROW|short-through-junction/%s|expanded=%v|same=%v", r.id, ok,
				ok && strings.EqualFold(filepath.Clean(filepath.FromSlash(got)), long))
			if !ok {
				t.Fatalf("an 8.3 spelling through a junction was not expanded (rel expanded it)")
			}
			if !strings.EqualFold(filepath.Clean(filepath.FromSlash(got)), long) {
				t.Fatalf("expanded to %q, want the long spelling through the junction %q", got, long)
			}
			want := ActionCommandDecision("echo ordinary > "+long, cwd, home)
			if want != "" {
				t.Fatalf("the long spelling decision = %q, want none", want)
			}
			if decision := ActionCommandDecision("echo ordinary > "+value, cwd, home); decision != want {
				t.Fatalf("the 8.3 spelling decision = %q, want %q as for the long spelling", decision, want)
			}
		})
	}
	t.Run("plain-short-name", func(t *testing.T) {
		long := filepath.Join(target, "Another Long Name", "file with long name.txt")
		got, ok := actionWindowsExpandShortPath(short(t, long))
		if !ok || !strings.EqualFold(filepath.Clean(filepath.FromSlash(got)), long) {
			t.Fatalf("a plain 8.3 spelling expanded to %q (%v), want %q", got, ok, long)
		}
	})
	t.Run("wildcard-component", func(t *testing.T) {
		if got, ok := actionWindowsExpandShortPath(filepath.Join(base, "jn", "ANOTHE~*", "x")); ok {
			t.Fatalf("a wildcard 8.3 component expanded to %q", got)
		}
	})
}
