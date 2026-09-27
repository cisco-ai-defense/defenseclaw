// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxauth

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// forbiddenFS fails the test on any host filesystem access.
type forbiddenFS struct {
	t     *testing.T
	mu    sync.Mutex
	calls []string
}

func (f *forbiddenFS) record(op, name string) {
	f.mu.Lock()
	f.calls = append(f.calls, op+" "+name)
	f.mu.Unlock()
	f.t.Errorf("copy-mode view touched the host filesystem: %s %s", op, name)
}

func (f *forbiddenFS) Lstat(name string) (fs.FileInfo, error) {
	f.record("lstat", name)
	return nil, fs.ErrNotExist
}

func (f *forbiddenFS) EvalSymlinks(name string) (string, error) {
	f.record("evalsymlinks", name)
	return "", fs.ErrNotExist
}

func (f *forbiddenFS) OpenInRoot(root, name string) (fs.File, error) {
	f.record("open", filepath.Join(root, name))
	return nil, fs.ErrNotExist
}

func TestCopyModeViewNeverTouchesHost(t *testing.T) {
	fsys := &forbiddenFS{t: t}
	host := t.TempDir()
	b := Binding{Workdir: Workdir{
		Mode: WorkdirCopy,
		// Even a recorded context mount grants nothing in copy mode.
		Mounts: []Mount{{SandboxPath: "/work/app", HostPath: host}},
	}}
	view := NewFSView(b, fsys)
	if view.HostAccess() || view.Mode() != WorkdirCopy {
		t.Fatal("copy-mode view claims host access")
	}
	for _, p := range []string{"/work/app", "/work/app/src/main.go", host, filepath.Join(host, "x"), "/etc/passwd", "relative"} {
		if _, err := view.HostPath(p); !errors.Is(err, ErrNoHostView) {
			t.Errorf("HostPath(%q) = %v", p, err)
		}
		if _, err := view.HostDir(p); !errors.Is(err, ErrNoHostView) {
			t.Errorf("HostDir(%q) = %v", p, err)
		}
		if _, err := view.ContainHostPath(p); !errors.Is(err, ErrNoHostView) {
			t.Errorf("ContainHostPath(%q) = %v", p, err)
		}
		if _, _, err := view.ReadFile(p, 1024); !errors.Is(err, ErrNoHostView) {
			t.Errorf("ReadFile(%q) = %v", p, err)
		}
		if _, ok := view.SandboxPath(p); ok {
			t.Errorf("SandboxPath(%q) mapped in copy mode", p)
		}
	}
	// Through the request context too.
	ctx := WithRequest(context.Background(), b, view)
	if got, ok := ViewFromContext(ctx); !ok || got != view {
		t.Fatal("context lost the view")
	}
	if len(fsys.calls) != 0 {
		t.Fatalf("host calls: %v", fsys.calls)
	}
}

type project struct {
	root    string // host project root as mounted (may contain symlinks, e.g. /var on macOS)
	real    string // its real path
	outside string // a host directory outside the mount
	view    *FSView
}

func newProject(t *testing.T, extraMounts ...Mount) project {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "app")
	outside := filepath.Join(base, "home")
	for _, dir := range []string{
		filepath.Join(root, "src"), filepath.Join(root, ".git"), filepath.Join(root, "certs"), outside,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, content string) {
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "src", "main.go"), "package main\n")
	write(filepath.Join(root, ".env"), "SECRET=1\n")
	write(filepath.Join(root, "certs", "dev.pem"), "-----BEGIN-----\n")
	write(filepath.Join(root, ".git", "config"), "[core]\n")
	write(filepath.Join(outside, "id_rsa"), "PRIVATE\n")
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	mounts := append([]Mount{{SandboxPath: "/work/app", HostPath: root}}, extraMounts...)
	b := Binding{Workdir: Workdir{
		Mode:   WorkdirMount,
		Mounts: mounts,
		Masks:  []string{"/work/app/.env", "/work/app/certs"},
	}}
	return project{root: root, real: real, outside: outside, view: NewFSView(b, nil)}
}

func TestMountViewMapsProjectPaths(t *testing.T) {
	p := newProject(t)
	got, err := p.view.HostPath("/work/app/src/main.go")
	if err != nil || got != filepath.Join(p.real, "src", "main.go") {
		t.Fatalf("HostPath = %q, %v", got, err)
	}
	if got, err := p.view.HostDir("/work/app/src/../src/"); err != nil || got != filepath.Join(p.real, "src") {
		t.Fatalf("HostDir = %q, %v", got, err)
	}
	if got, err := p.view.HostDir("/work/app"); err != nil || got != p.real {
		t.Fatalf("HostDir(root) = %q, %v", got, err)
	}
	if _, err := p.view.HostDir("/work/app/src/main.go"); err == nil {
		t.Fatal("HostDir accepted a file")
	}
	if _, err := p.view.HostPath("/work/app/missing.go"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing path: %v", err)
	}
	if got, ok := p.view.SandboxPath(filepath.Join(p.real, "src", "main.go")); !ok || got != "/work/app/src/main.go" {
		t.Fatalf("SandboxPath(real) = %q %v", got, ok)
	}
	if got, ok := p.view.SandboxPath(filepath.Join(p.root, "src")); !ok || got != "/work/app/src" {
		t.Fatalf("SandboxPath(lexical) = %q %v", got, ok)
	}
	if _, ok := p.view.SandboxPath(p.outside); ok {
		t.Fatal("SandboxPath mapped a path outside the mount")
	}
	data, info, err := p.view.ReadFile("/work/app/src/main.go", 1024)
	if err != nil || string(data) != "package main\n" || !info.Mode().IsRegular() {
		t.Fatalf("ReadFile = %q %v", data, err)
	}
	data, _, err = p.view.ReadFile(filepath.Join(p.real, "src", "main.go"), 1024)
	if err != nil || string(data) != "package main\n" {
		t.Fatalf("ReadFile(host path) = %q %v", data, err)
	}
	if got, err := p.view.ContainHostPath(filepath.Join(p.root, "src", "main.go")); err != nil ||
		got != filepath.Join(p.real, "src", "main.go") {
		t.Fatalf("ContainHostPath = %q %v", got, err)
	}
}

func TestMountViewRefusesEscapes(t *testing.T) {
	p := newProject(t)
	if err := os.Symlink(filepath.Join(p.outside, "id_rsa"), filepath.Join(p.root, "src", "key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p.outside, filepath.Join(p.root, "home")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../home/id_rsa", filepath.Join(p.root, "src", "rel")); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		"/work/app/src/key",           // absolute link out of the project
		"/work/app/home/id_rsa",       // linked directory out of the project
		"/work/app/src/rel",           // relative link out of the project
		"/work/app/../../etc/passwd",  // lexical escape
		"/work/other/file",            // not a mount
		"/etc/passwd",                 // not a mount
		"work/app/src/main.go",        // relative
		"",                            // empty
		"/work/app/src/main.go\x00.x", // NUL
	}
	for _, name := range cases {
		if _, err := p.view.HostPath(name); err == nil {
			t.Errorf("HostPath(%q) escaped", name)
		} else if !errors.Is(err, ErrOutsideView) && !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("HostPath(%q) = %v", name, err)
		}
		if _, _, err := p.view.ReadFile(name, 1024); err == nil {
			t.Errorf("ReadFile(%q) escaped", name)
		}
	}
	if _, err := p.view.ContainHostPath(filepath.Join(p.outside, "id_rsa")); !errors.Is(err, ErrOutsideView) {
		t.Fatalf("ContainHostPath(outside) = %v", err)
	}
	if _, err := p.view.ContainHostPath(filepath.Join(p.root, "src", "key")); !errors.Is(err, ErrOutsideView) {
		t.Fatalf("ContainHostPath(link out) = %v", err)
	}
	if _, err := p.view.ContainHostPath(filepath.Join(p.root, "..", "home", "id_rsa")); !errors.Is(err, ErrOutsideView) {
		t.Fatalf("ContainHostPath(dotdot) = %v", err)
	}
}

func TestMountViewFollowsLinksInsideProject(t *testing.T) {
	p := newProject(t)
	if err := os.Symlink("main.go", filepath.Join(p.root, "src", "alias.go")); err != nil {
		t.Fatal(err)
	}
	got, err := p.view.HostPath("/work/app/src/alias.go")
	if err != nil || got != filepath.Join(p.real, "src", "main.go") {
		t.Fatalf("HostPath(alias) = %q %v", got, err)
	}
	data, _, err := p.view.ReadFile("/work/app/src/alias.go", 1024)
	if err != nil || string(data) != "package main\n" {
		t.Fatalf("ReadFile(alias) = %q %v", data, err)
	}
}

func TestMountViewRefusesMasks(t *testing.T) {
	p := newProject(t)
	if err := os.Symlink("../.env", filepath.Join(p.root, "src", "env-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(p.root, ".env"), filepath.Join(p.root, "src", "env-hardlink")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"/work/app/.env",
		"/work/app/certs/dev.pem",
		"/work/app/certs",
		filepath.Join(p.root, ".env"),
		filepath.Join(p.real, "certs", "dev.pem"),
	} {
		if _, _, err := p.view.ReadFile(name, 1024); !errors.Is(err, ErrMasked) {
			t.Errorf("ReadFile(%q) = %v, want ErrMasked", name, err)
		}
	}
	for _, name := range []string{"/work/app/.env", "/work/app/src/env-link", "/work/app/certs/dev.pem"} {
		if _, err := p.view.HostPath(name); !errors.Is(err, ErrMasked) {
			t.Errorf("HostPath(%q) = %v, want ErrMasked", name, err)
		}
	}
	// A symlink or hard link to a mask is refused by the identity of the
	// opened file, not only by name.
	for _, name := range []string{"/work/app/src/env-link", "/work/app/src/env-hardlink"} {
		if _, _, err := p.view.ReadFile(name, 1024); !errors.Is(err, ErrMasked) {
			t.Errorf("ReadFile(%q) = %v, want ErrMasked", name, err)
		}
	}
}

// foldingFS presents the host tree below root the way a case-insensitive
// volume (APFS, NTFS) does: a name matches whatever its letter case, and
// EvalSymlinks keeps the spelling it was given. The project fixture names
// every file in lower case.
type foldingFS struct{ root string }

func (f foldingFS) fold(name string) string {
	rel, ok := hostRel(f.root, name)
	if !ok || rel == "" {
		return name
	}
	return filepath.Join(f.root, strings.ToLower(filepath.FromSlash(rel)))
}

func (f foldingFS) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(f.fold(name)) }

func (f foldingFS) EvalSymlinks(name string) (string, error) {
	if _, err := filepath.EvalSymlinks(f.fold(name)); err != nil {
		return "", err
	}
	return filepath.Clean(name), nil
}

func (f foldingFS) OpenInRoot(root, name string) (fs.File, error) {
	return OSFS{}.OpenInRoot(root, strings.ToLower(name))
}

// TestMountViewRefusesMasksUnderAnotherSpelling covers a case-insensitive
// host volume: the sandbox is case-sensitive, so /work/app/.ENV is not a
// mask there, yet on the host it opens the masked .env, and
// /work/app/CERTS/dev.pem lies inside the masked certs directory.
func TestMountViewRefusesMasksUnderAnotherSpelling(t *testing.T) {
	p := newProject(t)
	b := Binding{Workdir: Workdir{
		Mode:   WorkdirMount,
		Mounts: []Mount{{SandboxPath: "/work/app", HostPath: p.root}},
		Masks:  []string{"/work/app/.env", "/work/app/certs"},
	}}
	view := NewFSView(b, foldingFS{root: p.root})
	for _, name := range []string{
		"/work/app/.ENV",
		"/work/app/.Env",
		"/work/app/CERTS/dev.pem",
		"/work/app/Certs/DEV.PEM",
		filepath.Join(p.root, "CERTS", "dev.pem"),
	} {
		if _, _, err := view.ReadFile(name, 1024); !errors.Is(err, ErrMasked) {
			t.Errorf("ReadFile(%q) = %v, want ErrMasked", name, err)
		}
		if _, err := view.HostPath(name); !errors.Is(err, ErrMasked) && strings.HasPrefix(name, "/work/") {
			t.Errorf("HostPath(%q) = %v, want ErrMasked", name, err)
		}
	}
	// Other spellings of unmasked files still resolve.
	if data, _, err := view.ReadFile("/work/app/SRC/main.go", 1024); err != nil || string(data) != "package main\n" {
		t.Fatalf("ReadFile of an unmasked spelling = %q, %v", data, err)
	}
	if _, err := view.HostPath("/work/app/Src/Main.go"); err != nil {
		t.Fatalf("HostPath of an unmasked spelling: %v", err)
	}
}

// TestMountViewRefusesLinksIntoMaskedDirectories covers the links an agent
// can plant in the project: a symlink to a masked directory and a hard
// link to a masked file.
func TestMountViewRefusesLinksIntoMaskedDirectories(t *testing.T) {
	p := newProject(t)
	if err := os.Symlink("../certs", filepath.Join(p.root, "src", "certs-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(p.root, ".env"), filepath.Join(p.root, "src", "env-hardlink")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"/work/app/src/certs-link/dev.pem", "/work/app/src/env-hardlink"} {
		if _, _, err := p.view.ReadFile(name, 1024); !errors.Is(err, ErrMasked) {
			t.Errorf("ReadFile(%q) = %v, want ErrMasked", name, err)
		}
		if _, err := p.view.HostPath(name); !errors.Is(err, ErrMasked) {
			t.Errorf("HostPath(%q) = %v, want ErrMasked", name, err)
		}
	}
}

func TestMountViewReadFileLimits(t *testing.T) {
	p := newProject(t)
	if _, _, err := p.view.ReadFile("/work/app/src/main.go", 4); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size limit: %v", err)
	}
	if _, _, err := p.view.ReadFile("/work/app/src", 1024); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directory: %v", err)
	}
	if _, _, err := p.view.ReadFile("/work/app/src/main.go", 0); err == nil {
		t.Fatal("zero limit accepted")
	}
	fifo := filepath.Join(p.root, "src", "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := p.view.ReadFile("/work/app/src/pipe", 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("fifo: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFile blocked on a FIFO planted in the project")
	}
}

func TestMountViewNestedMountsUseLongestPrefix(t *testing.T) {
	base := t.TempDir()
	lib := filepath.Join(base, "lib")
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lib, "README"), []byte("lib\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := newProject(t, Mount{SandboxPath: "/work/app/vendor/lib", HostPath: lib, ReadOnly: true})
	data, _, err := p.view.ReadFile("/work/app/vendor/lib/README", 1024)
	if err != nil || string(data) != "lib\n" {
		t.Fatalf("nested mount read = %q %v", data, err)
	}
	realLib, _ := filepath.EvalSymlinks(lib)
	if got, err := p.view.HostPath("/work/app/vendor/lib"); err != nil || got != realLib {
		t.Fatalf("nested mount root = %q %v", got, err)
	}
	if got, ok := p.view.SandboxPath(filepath.Join(realLib, "README")); !ok || got != "/work/app/vendor/lib/README" {
		t.Fatalf("SandboxPath(nested) = %q %v", got, ok)
	}
}

func TestMountViewMissingRootFailsClosed(t *testing.T) {
	b := Binding{Workdir: Workdir{Mode: WorkdirMount, Mounts: []Mount{{SandboxPath: "/work/app", HostPath: "/nonexistent/defenseclaw/app"}}}}
	view := NewFSView(b, nil)
	if _, err := view.HostPath("/work/app/x"); err == nil {
		t.Fatal("missing mount root resolved")
	}
	if _, _, err := view.ReadFile("/work/app/x", 10); err == nil {
		t.Fatal("missing mount root read")
	}
}

func TestContextHelpers(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("background context has a binding")
	}
	if _, ok := ViewFromContext(nil); ok { //nolint:staticcheck // nil context is part of the contract
		t.Fatal("nil context has a view")
	}
	b := Binding{ID: "sb_x", Routes: []Route{RouteHook}, Workdir: Workdir{Mode: WorkdirCopy}}
	ctx := WithRequest(context.Background(), b, nil)
	got, ok := FromContext(ctx)
	if !ok || got.ID != "sb_x" {
		t.Fatalf("FromContext = %+v %v", got, ok)
	}
	got.Routes[0] = RouteOTLP
	if again, _ := FromContext(ctx); again.Routes[0] != RouteHook {
		t.Fatal("FromContext returned an alias")
	}
	if view, ok := ViewFromContext(ctx); !ok || view == nil || view.HostAccess() {
		t.Fatal("nil view was not replaced by the binding's view")
	}
}
