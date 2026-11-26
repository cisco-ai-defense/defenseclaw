// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// gap2243ShortPath is the 8.3 spelling of an existing path; it skips when
// the volume makes no short names.
func gap2243ShortPath(t *testing.T, path string) string {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		t.Fatalf("GetShortPathName(%s): %v", path, err)
	}
	short := windows.UTF16ToString(buffer[:n])
	if !strings.Contains(short, "~") || strings.EqualFold(short, path) {
		t.Skipf("the volume of %s makes no 8.3 short names", path)
	}
	return short
}

// GAP-2243: an HKLM Claude matrix that names the installed hook by its 8.3
// alias starts the hook by that alias. The managed runtime must resolve as it
// does for the long name, not fail closed with
// enterprise_managed_runtime_drift on every tool call.
func TestGAP2243ClaudeManagedRuntimeAcceptsTheInstalledHookByItsShortName(t *testing.T) {
	requireGAP633Elevated(t) // the managed policy install refuses a standard-user token (GAP-2263)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	want, err := ResolveWindowsManagedHookRuntime(fixture.hookExe, "claudecode")
	if err != nil || !want.Registered || want.GenerationID == "" {
		t.Fatalf("long-path runtime: %+v err=%v", want, err)
	}
	// The exec form names the hook by the alias of every component; the
	// guarded wrapper wa1 names its folder by alias and keeps the long file
	// name, and the guard starts the hook by that spelling.
	for name, alias := range map[string]string{
		"exec form, every name by alias": gap2243ShortPath(t, fixture.hookExe),
		"wa1, folder by alias":           filepath.Join(gap2243ShortPath(t, filepath.Dir(fixture.hookExe)), filepath.Base(fixture.hookExe)),
	} {
		got, err := ResolveWindowsManagedHookRuntime(alias, "claudecode")
		if err != nil {
			t.Errorf("%s: %s: class=%q err=%v", name, alias, WindowsManagedRuntimeFailureClassOf(err), err)
			continue
		}
		if !got.Registered || got.GenerationID != want.GenerationID || got.ScopedToken != want.ScopedToken ||
			got.GatewayAddr != want.GatewayAddr || got.FailMode != want.FailMode {
			t.Errorf("%s: %s: runtime = %+v, want %+v", name, alias, got, want)
		}
	}
}

// GAP-2243 negative guard: only the installed file by its own names is the
// hook. A copy elsewhere, another file in the hook folder and a hard link in
// another folder stay refused as a boundary, by long name and by 8.3 alias.
func TestGAP2243ClaudeManagedRuntimeRefusesOtherFilesByAnySpelling(t *testing.T) {
	requireGAP633Elevated(t) // the managed policy install refuses a standard-user token (GAP-2263)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(fixture.hookExe)
	if err != nil {
		t.Fatal(err)
	}
	scope := filepath.Dir(filepath.Dir(fixture.hookExe))
	copyElsewhere := filepath.Join(scope, "elsewhere folder", "defenseclaw-hook.exe")
	sibling := filepath.Join(filepath.Dir(fixture.hookExe), "defenseclaw-hook-copy.exe")
	hardLink := filepath.Join(scope, "linked folder", "defenseclaw-hook.exe")
	for _, path := range []string{copyElsewhere, sibling} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(hardLink), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(fixture.hookExe, hardLink); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"copy elsewhere":          copyElsewhere,
		"copy elsewhere by alias": gap2243ShortPath(t, copyElsewhere),
		"sibling by alias":        gap2243ShortPath(t, sibling),
		"hard link":               hardLink,
		"hard link by alias":      gap2243ShortPath(t, hardLink),
	}
	for name, path := range cases {
		runtime, err := ResolveWindowsManagedHookRuntime(path, "claudecode")
		if err == nil || runtime.Registered ||
			WindowsManagedRuntimeFailureClassOf(err) != WindowsManagedRuntimeFailureBoundary || runtime.FailMode != "" {
			t.Errorf("%s (%s): runtime=%+v class=%q err=%v, want a boundary refusal",
				name, path, runtime, WindowsManagedRuntimeFailureClassOf(err), err)
		}
	}
}
