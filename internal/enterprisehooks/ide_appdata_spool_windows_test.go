// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"archive/zip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/inventory/ideplugins"
	"golang.org/x/sys/windows"
)

// A redirected AppData folder is read only when it is a folder the account
// owns, reached without a junction; a missing one is skipped quietly
// (GAP-1249).
func TestRedirectedAppDataFolderMustBeOwnedAndReachedWithoutAJunction(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, "Redirected", "alice", "Roaming")
	other := filepath.Join(root, "Users", "bob", "AppData", "Roaming")
	for _, dir := range []string{folder, other, filepath.Join(root, "Users", "carol", "AppData", "Roaming")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	junction := func(link, target string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, out)
		}
	}
	sd, err := windows.GetNamedSecurityInfo(folder, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ownerSID, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	owner := ownerSID.String()
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	refused := func(sid, path, reason string) {
		t.Helper()
		logged = nil
		if got := windowsUsableIDEAppDataFolder(sid, path, logf); got != "" {
			t.Errorf("%s is read for %s, want refused (%s)", path, sid, reason)
		}
		if len(logged) != 1 || !strings.Contains(logged[0], reason) {
			t.Errorf("%s: logged %q, want %q", path, logged, reason)
		}
	}
	if got := windowsUsableIDEAppDataFolder(owner, folder, logf); got != folder {
		t.Fatalf("the owner's own folder = %q, want %q (logged %q)", got, folder, logged)
	}
	refused("S-1-5-21-1000000001-1000000002-1000000003-1001", folder, "the account does not own it")
	// The folder replaced by a junction to another profile's folder, which
	// the same account owns.
	swapped := filepath.Join(root, "Redirected", "alice", "Roaming2")
	junction(swapped, other)
	refused(owner, swapped, "a link or junction leads to it")
	// A junction above the folder.
	junction(filepath.Join(root, "Redirected", "carol"), filepath.Join(root, "Users", "carol"))
	refused(owner, filepath.Join(root, "Redirected", "carol", "AppData", "Roaming"), "a link or junction leads to it")
	file := filepath.Join(root, "Redirected", "alice", "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	refused(owner, file, "it is not a folder")
	logged = nil
	if got := windowsUsableIDEAppDataFolder(owner, filepath.Join(root, "Redirected", "dave", "Roaming"), logf); got != "" || len(logged) != 0 {
		t.Errorf("a missing folder = %q, logged %q; want skipped quietly", got, logged)
	}
}

// writeIDEPluginJar writes a JetBrains plugin jar of id below roaming.
func writeIDEPluginJar(t *testing.T, roaming, id string) {
	t.Helper()
	path := filepath.Join(roaming, "JetBrains", "PyCharm2024.1", "plugins", id, "lib", id+".jar")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("META-INF/plugin.xml")
	if err == nil {
		_, err = fmt.Fprintf(w, "<idea-plugin><id>com.example.%s</id><name>%s</name><version>1.0</version></idea-plugin>", id, id)
	}
	if err == nil {
		err = zw.Close()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
}

func hasIDEPlugin(installs []ideplugins.Install, id string) bool {
	for _, inst := range installs {
		for _, p := range inst.Plugins {
			if p.ID == "com.example."+id {
				return true
			}
		}
	}
	return false
}

// redirectedAppDataSwap lays out alice's profile, her redirected roaming
// folder with her plugin, and an ordinary folder with bob's plugin that is
// swapped in for it.
type redirectedAppDataSwap struct {
	root, home, parent, folder, staged string
	record                             IDEAppDataSpoolRecord
}

func newRedirectedAppDataSwap(t *testing.T) redirectedAppDataSwap {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l := redirectedAppDataSwap{
		root: root, home: filepath.Join(root, "Users", "alice"),
		parent: filepath.Join(root, "Redirected", "alice"),
		staged: filepath.Join(root, "Staged", "Roaming"),
	}
	l.folder = filepath.Join(l.parent, "Roaming")
	if err := os.MkdirAll(l.home, 0o755); err != nil {
		t.Fatal(err)
	}
	writeIDEPluginJar(t, l.folder, "alice-tool")
	writeIDEPluginJar(t, l.staged, "bob-tool")
	sd, err := windows.GetNamedSecurityInfo(l.folder, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	l.record = IDEAppDataSpoolRecord{
		Version: IDEAppDataSpoolRecordVersion, Key: owner.String(), Home: l.home, RoamingAppData: l.folder,
	}
	return l
}

// swapFolder renames the redirected folder away and the staged one into its
// place.
func (l redirectedAppDataSwap) swapFolder() []error {
	return []error{os.Rename(l.folder, l.folder+".alice"), os.Rename(l.staged, l.folder)}
}

// swapParent renames the folder above the redirected one away and puts the
// staged folder at the redirected path.
func (l redirectedAppDataSwap) swapParent() []error {
	errs := []error{os.Rename(l.parent, l.parent+".alice")}
	errs = append(errs, os.MkdirAll(l.parent, 0o755))
	return append(errs, os.Rename(l.staged, l.folder))
}

// The redirected folder swapped, between its check and its scan, for
// another ordinary folder at the same path: that folder's plugins are never
// published for the profile. The check holds the folder through the scan,
// and the path must still name it afterwards (GAP-1249).
func TestRedirectedAppDataSwappedAfterItsCheckIsNotPublished(t *testing.T) {
	// Control: a check that is not held through the scan does not stop the
	// swap (the enumerator before this fix).
	control := newRedirectedAppDataSwap(t)
	if got := windowsUsableIDEAppDataFolder(control.record.Key, control.folder, nil); got != control.folder {
		t.Fatalf("the owner's folder = %q, want %q", got, control.folder)
	}
	if errs := control.swapFolder(); errs[0] != nil || errs[1] != nil {
		t.Fatalf("control swap: %v", errs)
	}
	if !hasIDEPlugin(ideplugins.Scan(control.home, "windows", ideplugins.Limits{RoamingAppData: control.folder}), "bob-tool") {
		t.Fatal("control: the swapped folder was not read; the test does not exercise the swap")
	}

	for _, tc := range []struct {
		name string
		swap func(redirectedAppDataSwap) []error
	}{
		{"the redirected folder", redirectedAppDataSwap.swapFolder},
		{"the folder above it", redirectedAppDataSwap.swapParent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newRedirectedAppDataSwap(t)
			t.Cleanup(func() { beforeIDEAppDataScan = nil })
			var errs []error
			beforeIDEAppDataScan = func(IDEAppDataSpoolRecord) { errs = tc.swap(l) }
			var logged []string
			logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
			got, ok := windowsScanIDEAppData(l.record, logf)
			t.Logf("swap of %s while held: %v; published %v; logged %q", tc.name, errs, ok, logged)
			if ok && hasIDEPlugin(got.Installs, "bob-tool") {
				t.Fatalf("the swapped folder's plugin is published for the profile: %+v", got.Installs)
			}
			if ok && !hasIDEPlugin(got.Installs, "alice-tool") {
				t.Fatalf("published without the held folder's plugin: %+v", got.Installs)
			}
		})
	}

	// Unswapped: the held folder is read and published.
	l := newRedirectedAppDataSwap(t)
	got, ok := windowsScanIDEAppData(l.record, nil)
	if !ok || !hasIDEPlugin(got.Installs, "alice-tool") || hasIDEPlugin(got.Installs, "bob-tool") {
		t.Fatalf("unswapped scan = %v %+v, want alice's plugin only", ok, got.Installs)
	}
}
