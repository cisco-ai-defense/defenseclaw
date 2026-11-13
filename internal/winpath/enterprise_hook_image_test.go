// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testHookSHA  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testGuardSHA = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	testBin      = `C:\Program Files\Cisco\DefenseClaw\bin`
)

func TestParseEnterpriseHookImagePath(t *testing.T) {
	cases := []struct {
		path   string
		ok     bool
		bin    string
		digest string
	}{
		{testBin + `\defenseclaw-hook.exe`, true, testBin, ""},
		{testBin + `\DefenseClaw-Hook.EXE`, true, testBin, ""},
		{testBin + `\defenseclaw-hook-guard.exe`, true, testBin, ""},
		{testBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`, true, testBin, "0123456789abcdef"},
		{testBin + `\HOOKS\0123456789abcdef\defenseclaw-hook-guard.exe`, true, testBin, "0123456789abcdef"},
		{`C:/Program Files/Cisco/DefenseClaw/bin/hooks/0123456789abcdef/defenseclaw-hook.exe`, true, testBin, "0123456789abcdef"},
		// The folder name is exactly 16 hex digits; Windows names ignore case.
		{testBin + `\hooks\0123456789ABCDEF\defenseclaw-hook.exe`, true, testBin, "0123456789abcdef"},
		{testBin + `\hooks\0123456789abcdeg\defenseclaw-hook.exe`, false, "", ""},
		{testBin + `\hooks\0123456789abcde\defenseclaw-hook.exe`, false, "", ""},
		{testBin + `\hooks\0123456789abcdef0\defenseclaw-hook.exe`, false, "", ""},
		{testBin + `\hooks\.staging-0123456789abcdef\defenseclaw-hook.exe`, false, "", ""},
		{testBin + `\other\0123456789abcdef\defenseclaw-hook.exe`, false, "", ""},
		{testBin + `\hooks\defenseclaw-hook.exe`, false, "", ""},
		{`C:\Program Files\Cisco\DefenseClaw\lib\defenseclaw-hook.exe`, false, "", ""},
		{testBin + `\defenseclaw-gateway.exe`, false, "", ""},
		{`C:\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`, true, `C:\bin`, "0123456789abcdef"},
		{`bin\defenseclaw-hook.exe`, false, "", ""},
		{`\\server\share\bin\defenseclaw-hook.exe`, false, "", ""},
		{"", false, "", ""},
	}
	for _, tc := range cases {
		got, ok := ParseEnterpriseHookImagePath(tc.path)
		if ok != tc.ok || got.Bin != tc.bin || got.Digest != tc.digest {
			t.Errorf("ParseEnterpriseHookImagePath(%q) = %+v, %v; want bin %q digest %q ok %v", tc.path, got, ok, tc.bin, tc.digest, tc.ok)
		}
		if ok && got.Versioned() != (tc.digest != "") {
			t.Errorf("Versioned(%q) = %v", tc.path, got.Versioned())
		}
	}
}

func TestSameEnterpriseHookImageFamily(t *testing.T) {
	fixed := testBin + `\defenseclaw-hook.exe`
	launch := testBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	older := testBin + `\hooks\aaaaaaaaaaaaaaaa\defenseclaw-hook.exe`
	guard := testBin + `\hooks\0123456789abcdef\defenseclaw-hook-guard.exe`
	otherRoot := `C:\Program Files\Cisco\Other\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{fixed, launch, true},
		{launch, older, true},
		{strings.ToUpper(launch), older, true},
		{launch, launch, true},
		{launch, guard, false},
		{launch, otherRoot, false},
		{launch, testBin + `\defenseclaw-gateway.exe`, false},
		{"", launch, false},
	} {
		if got := SameEnterpriseHookImageFamily(tc.a, tc.b); got != tc.want {
			t.Errorf("SameEnterpriseHookImageFamily(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
	if got := EnterpriseHookImageBin(older); got != testBin {
		t.Fatalf("EnterpriseHookImageBin = %q", got)
	}
	if got := EnterpriseHookImageBin(testBin + `\defenseclaw.exe`); got != "" {
		t.Fatalf("EnterpriseHookImageBin(non-hook) = %q", got)
	}
}

func TestEnterpriseHookImageDir(t *testing.T) {
	dir, err := EnterpriseHookImageDir(testBin+`\`, strings.ToUpper(testHookSHA))
	if err != nil || dir != testBin+`\hooks\0123456789abcdef` {
		t.Fatalf("EnterpriseHookImageDir = %q, %v", dir, err)
	}
	for _, bad := range []string{"", "0123", testHookSHA + "00", strings.Repeat("g", 64)} {
		if _, err := EnterpriseHookImageDir(testBin, bad); err == nil {
			t.Errorf("EnterpriseHookImageDir(%q) accepted", bad)
		}
	}
	if got := EnterpriseHookImagesRoot(testBin); got != testBin+`\hooks` {
		t.Fatalf("EnterpriseHookImagesRoot = %q", got)
	}
}

type fakeHookFile struct {
	dir     bool
	symlink bool
	size    int64
	digest  string
	err     error
}

type fakeHookImageFS struct {
	files  map[string]fakeHookFile
	hashes int
}

type fakeInfo struct {
	name string
	file fakeHookFile
}

func (i fakeInfo) Name() string { return i.name }
func (i fakeInfo) Size() int64  { return i.file.size }
func (i fakeInfo) Mode() fs.FileMode {
	switch {
	case i.file.symlink:
		return fs.ModeSymlink
	case i.file.dir:
		return fs.ModeDir
	}
	return 0
}
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return i.file.dir }
func (i fakeInfo) Sys() any           { return nil }

func (f *fakeHookImageFS) Lstat(name string) (fs.FileInfo, error) {
	file, ok := f.files[strings.ToLower(name)]
	if !ok {
		return nil, fs.ErrNotExist
	}
	if file.err != nil {
		return nil, file.err
	}
	return fakeInfo{name: name, file: file}, nil
}

func (f *fakeHookImageFS) FileSHA256(name string) (string, error) {
	f.hashes++
	file, ok := f.files[strings.ToLower(name)]
	if !ok {
		return "", fs.ErrNotExist
	}
	if file.dir {
		return "", errors.New("is a folder")
	}
	return file.digest, nil
}

func (f *fakeHookImageFS) put(path string, file fakeHookFile) {
	if f.files == nil {
		f.files = map[string]fakeHookFile{}
	}
	f.files[strings.ToLower(path)] = file
}

func stagedFS(t *testing.T) *fakeHookImageFS {
	t.Helper()
	f := &fakeHookImageFS{}
	f.put(testBin+`\defenseclaw-hook.exe`, fakeHookFile{size: 10, digest: testHookSHA})
	f.put(testBin+`\defenseclaw-hook-guard.exe`, fakeHookFile{size: 5, digest: testGuardSHA})
	f.put(testBin+`\hooks`, fakeHookFile{dir: true})
	f.put(testBin+`\hooks\0123456789abcdef`, fakeHookFile{dir: true})
	f.put(testBin+`\hooks\0123456789abcdef\defenseclaw-hook.exe`, fakeHookFile{size: 10, digest: testHookSHA})
	f.put(testBin+`\hooks\0123456789abcdef\defenseclaw-hook-guard.exe`, fakeHookFile{size: 5, digest: testGuardSHA})
	return f
}

func TestResolveEnterpriseHookImageStaged(t *testing.T) {
	got := ResolveEnterpriseHookImageWith(stagedFS(t), testBin)
	if got.State != EnterpriseHookImageStaged ||
		got.Hook != testBin+`\hooks\0123456789abcdef\defenseclaw-hook.exe` ||
		got.Guard != testBin+`\hooks\0123456789abcdef\defenseclaw-hook-guard.exe` ||
		got.SHA256 != testHookSHA || got.Problem != "" {
		t.Fatalf("staged resolve = %+v", got)
	}
}

func TestResolveEnterpriseHookImageLegacyLayout(t *testing.T) {
	f := &fakeHookImageFS{}
	f.put(testBin+`\defenseclaw-hook.exe`, fakeHookFile{size: 10, digest: testHookSHA})
	got := ResolveEnterpriseHookImageWith(f, testBin)
	// Secure Client: no guard, no hooks folder: the 1.0.9 path, unchanged.
	if got.State != EnterpriseHookImageLegacyLayout || got.Hook != testBin+`\defenseclaw-hook.exe` || got.Guard != "" {
		t.Fatalf("legacy resolve = %+v", got)
	}
	f.put(testBin+`\defenseclaw-hook-guard.exe`, fakeHookFile{size: 5, digest: testGuardSHA})
	got = ResolveEnterpriseHookImageWith(f, testBin)
	if got.State != EnterpriseHookImageLegacyLayout || got.Guard != testBin+`\defenseclaw-hook-guard.exe` {
		t.Fatalf("legacy resolve with guard = %+v", got)
	}
}

func TestResolveEnterpriseHookImageFallsBackToTransitionImage(t *testing.T) {
	transition := testBin + `\defenseclaw-hook.exe`
	cases := map[string]func(*fakeHookImageFS){
		"no launch folder": func(f *fakeHookImageFS) {
			delete(f.files, strings.ToLower(testBin+`\hooks\0123456789abcdef`))
		},
		"launch image of another release": func(f *fakeHookImageFS) {
			f.put(testBin+`\hooks\0123456789abcdef\defenseclaw-hook.exe`, fakeHookFile{size: 10, digest: testGuardSHA})
		},
		"empty launch image": func(f *fakeHookImageFS) {
			f.put(testBin+`\hooks\0123456789abcdef\defenseclaw-hook.exe`, fakeHookFile{size: 0, digest: testHookSHA})
		},
		"launch image missing": func(f *fakeHookImageFS) {
			delete(f.files, strings.ToLower(testBin+`\hooks\0123456789abcdef\defenseclaw-hook.exe`))
		},
		"guard missing from the launch folder": func(f *fakeHookImageFS) {
			delete(f.files, strings.ToLower(testBin+`\hooks\0123456789abcdef\defenseclaw-hook-guard.exe`))
		},
		"guard of another release": func(f *fakeHookImageFS) {
			f.put(testBin+`\hooks\0123456789abcdef\defenseclaw-hook-guard.exe`, fakeHookFile{size: 5, digest: testHookSHA})
		},
		"hooks folder is a link": func(f *fakeHookImageFS) {
			f.put(testBin+`\hooks`, fakeHookFile{dir: true, symlink: true})
		},
		"launch folder is a link": func(f *fakeHookImageFS) {
			f.put(testBin+`\hooks\0123456789abcdef`, fakeHookFile{dir: true, symlink: true})
		},
		"hooks is a file": func(f *fakeHookImageFS) {
			f.put(testBin+`\hooks`, fakeHookFile{size: 3})
		},
		"hooks unreadable": func(f *fakeHookImageFS) {
			f.put(testBin+`\hooks`, fakeHookFile{err: os.ErrPermission})
		},
		"transition hook unreadable": func(f *fakeHookImageFS) {
			delete(f.files, strings.ToLower(transition))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := stagedFS(t)
			mutate(f)
			got := ResolveEnterpriseHookImageWith(f, testBin)
			if got.State != EnterpriseHookImageNotStaged || got.Hook != transition || got.Problem == "" {
				t.Fatalf("resolve = %+v; want the transition image, not_staged with a problem", got)
			}
			if got.Guard != "" && got.Guard != testBin+`\defenseclaw-hook-guard.exe` {
				t.Fatalf("fallback guard %q is not the transition guard", got.Guard)
			}
		})
	}
}

func TestHookImageDigestMemoRehashesANewObject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "defenseclaw-hook.exe")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	memo := &hookImageDigestMemo{}
	opens := 0
	open := func(name string) (*os.File, error) {
		opens++
		return os.Open(name)
	}
	first, err := memo.sha256(path, os.Lstat, open)
	if err != nil {
		t.Fatal(err)
	}
	again, err := memo.sha256(path, os.Lstat, open)
	if err != nil || again != first || opens != 1 {
		t.Fatalf("memo hit = %q, %v, opens %d", again, err, opens)
	}
	// A new object under the name (an atomic replace) is hashed again.
	replacement := filepath.Join(dir, "next")
	if err := os.WriteFile(replacement, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	second, err := memo.sha256(path, os.Lstat, open)
	if err != nil || second == first || opens != 2 {
		t.Fatalf("after replace = %q (first %q), %v, opens %d", second, first, err, opens)
	}
	if _, err := memo.sha256(dir, os.Lstat, open); err == nil {
		t.Fatal("memo hashed a folder")
	}
}
