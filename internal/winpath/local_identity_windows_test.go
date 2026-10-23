// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// setTestMountPoint makes the empty directory link a junction with the
// given substitute and print names, as any account can for a folder it
// owns, whatever target it names.
func setTestMountPoint(t *testing.T, link, substitute, print string) error {
	t.Helper()
	if err := os.Mkdir(link, 0o755); err != nil {
		t.Fatal(err)
	}
	ptr, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(ptr, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	data := reparseBuffer(reparseTagMountPoint, substitute, print, false)
	var returned uint32
	return windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &data[0], uint32(len(data)), nil, 0, &returned, nil)
}

func identityOf(t *testing.T, path string) LocalFileIdentity {
	t.Helper()
	identity, err := LocalPathIdentity(path)
	if err != nil {
		t.Fatalf("LocalPathIdentity(%s): %v", path, err)
	}
	return identity
}

// A junction or symbolic link to a local directory resolves to that
// directory; one to a share, a device or a volume is refused without being
// followed, even behind a local print name or a chain of local links.
func TestLocalPathIdentityFollowsOnlyLocalLinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "Users", "alice")
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	want := identityOf(t, home)
	if !want.Directory {
		t.Fatalf("home identity = %+v", want)
	}
	junction := filepath.Join(root, "junction")
	chain := filepath.Join(root, "chain")
	for link, target := range map[string]string{junction: home, chain: junction} {
		if err := setTestMountPoint(t, link, `\??\`+target, target); err != nil {
			t.Fatalf("junction %s: %v", link, err)
		}
	}
	// Links that must be refused. NTFS may refuse to store some of them; a
	// link it stores must never be followed.
	refused := []string{`\\127.0.0.1\` + strings.Replace(home, ":", "$", 1), `\\?\` + home, `\\.\` + home}
	share := filepath.Join(root, "share")
	for link, substitute := range map[string]string{
		share:                         `\??\UNC\127.0.0.1\` + strings.Replace(home, ":", "$", 1),
		filepath.Join(root, "volume"): `\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\`,
		filepath.Join(root, "mup"):    `\??\GLOBALROOT\Device\Mup\127.0.0.1\C$`,
	} {
		// The print name shows the local home; only the substitute is followed.
		if err := setTestMountPoint(t, link, substitute, home); err != nil {
			t.Logf("NTFS refused junction %s -> %s: %v", link, substitute, err)
			continue
		}
		refused = append(refused, link, filepath.Join(link, ".config"))
	}
	if _, err := os.Lstat(share); err == nil {
		toShare := filepath.Join(root, "to-share")
		if err := setTestMountPoint(t, toShare, `\??\`+share, share); err != nil {
			t.Fatal(err)
		}
		refused = append(refused, toShare)
	}
	if err := os.Symlink(`\\127.0.0.1\`+strings.Replace(home, ":", "$", 1), filepath.Join(root, "symlink-share")); err == nil {
		refused = append(refused, filepath.Join(root, "symlink-share"))
	} else {
		t.Logf("no symlink privilege: %v", err)
	}

	for _, path := range []string{junction, chain, strings.ToUpper(junction), junction + `\.config\..`} {
		if got := identityOf(t, path); got != want {
			t.Fatalf("%s identity = %+v, want %+v", path, got, want)
		}
	}
	if got := identityOf(t, filepath.Join(chain, ".config")); got == want || !got.Directory {
		t.Fatalf("child through a chain = %+v", got)
	}
	if err := os.Symlink(`Users\alice`, filepath.Join(root, "relative")); err == nil {
		if got := identityOf(t, filepath.Join(root, "relative")); got != want {
			t.Fatalf("relative symlink identity = %+v, want %+v", got, want)
		}
	}
	for _, path := range refused {
		if _, err := LocalPathIdentity(path); !errors.Is(err, ErrPathNotLocal) {
			t.Fatalf("LocalPathIdentity(%s) err = %v, want ErrPathNotLocal", path, err)
		}
	}
	for _, path := range []string{filepath.Join(home, "missing"), filepath.Join(junction, "missing", "child")} {
		if _, err := LocalPathIdentity(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("LocalPathIdentity(%s) err = %v, want fs.ErrNotExist", path, err)
		}
	}
}
