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

package openshell

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// fakeInode is one folder of a fake ext4 image.
type fakeInode struct {
	UID, GID int
	Mode     uint32
}

// fakeE2fs plays mke2fs and debugfs on fake images: the inode table is
// JSON at the start of the image file, so it travels with a rename.
type fakeE2fs struct {
	t        *testing.T
	formats  int
	writes   int
	brokenSi bool // debugfs -w ignores sif, as a broken debugfs would
	mkfsArgs []string
}

func (f *fakeE2fs) read(image string) map[string]fakeInode {
	raw, err := os.ReadFile(image)
	if err != nil {
		f.t.Fatalf("read %s: %v", image, err)
	}
	raw, _, _ = bytes.Cut(raw, []byte{0})
	table := map[string]fakeInode{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &table); err != nil {
			f.t.Fatalf("image %s: %v", image, err)
		}
	}
	return table
}

func (f *fakeE2fs) write(image string, table map[string]fakeInode) {
	raw, _ := json.Marshal(table)
	file, err := os.OpenFile(image, os.O_WRONLY, 0)
	if err != nil {
		f.t.Fatalf("open %s: %v", image, err)
	}
	defer file.Close()
	if _, err := file.WriteAt(append(raw, 0), 0); err != nil {
		f.t.Fatalf("write %s: %v", image, err)
	}
}

// writeImage makes an image of size bytes with the folders' owner.
func (f *fakeE2fs) writeImage(path string, size int64, uid, gid int) {
	must(f.t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(f.t, os.WriteFile(path, nil, 0o644))
	must(f.t, os.Truncate(path, size))
	table := map[string]fakeInode{}
	for _, name := range vmOverlayDirs {
		table[name] = fakeInode{UID: uid, GID: gid, Mode: 0o755}
	}
	f.write(path, table)
}

func (f *fakeE2fs) Run(context.Context, Command) error { return errors.New("not used") }

func (f *fakeE2fs) Output(_ context.Context, c Command) ([]byte, error) {
	args := c.Args
	image := args[len(args)-1]
	switch filepath.Base(c.Name) {
	case "mke2fs", "mkfs.ext4":
		f.formats++
		f.mkfsArgs = args
		f.write(image, map[string]fakeInode{})
		return nil, nil
	case "debugfs":
	default:
		return nil, fmt.Errorf("unexpected tool %s", c.Name)
	}
	table := f.read(image)
	switch {
	case len(args) == 3 && args[0] == "-R":
		name := strings.TrimPrefix(args[1], "stat ")
		ino, ok := table[name]
		if !ok {
			return []byte("debugfs 1.47.1\nstat: File not found by ext2_lookup while doing stat\n"), nil
		}
		return fmt.Appendf(nil, "debugfs 1.47.1\nInode: 14   Type: directory    Mode:  %04o   Flags: 0x80000\n"+
			"Generation: 0    Version: 0x00000000:00000000\nUser: %5d   Group: %5d   Project:     0   Size: 4096\n", ino.Mode, ino.UID, ino.GID), nil
	case len(args) == 4 && args[0] == "-w" && args[1] == "-f":
		f.writes++
		script, err := os.ReadFile(args[2])
		if err != nil {
			return nil, err
		}
		for line := range strings.Lines(string(script)) {
			fields := strings.Fields(line)
			switch {
			case len(fields) == 2 && fields[0] == "mkdir":
				// debugfs mkdir makes a folder as the umask of the
				// running user would; the script sets the owner after.
				table[fields[1]] = fakeInode{UID: 503, GID: 20, Mode: 0o700}
			case len(fields) == 4 && fields[0] == "sif" && !f.brokenSi:
				ino := table[fields[1]]
				n, err := strconv.ParseUint(fields[3], 8, 32)
				if fields[2] != "mode" {
					n, err = strconv.ParseUint(fields[3], 10, 32)
				}
				if err != nil {
					return nil, err
				}
				switch fields[2] {
				case "uid":
					ino.UID = int(n)
				case "gid":
					ino.GID = int(n)
				case "mode":
					ino.Mode = uint32(n) & 0o7777
				}
				table[fields[1]] = ino
			}
		}
		f.write(image, table)
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected debugfs args %q", args)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// toolsDir is a folder that holds executable mke2fs and debugfs.
func toolsDir(t *testing.T) string {
	dir := t.TempDir()
	for _, name := range []string{"mke2fs", "debugfs"} {
		must(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 1\n"), 0o755))
	}
	return dir
}

func TestVMOverlayTemplateLayout(t *testing.T) {
	for version, want := range map[string]string{
		"0.1.4": "", "0.1.5": vmOverlayTemplateLayoutV1, "0.1.6": vmOverlayTemplateLayoutV1, "openshell 0.1.6": vmOverlayTemplateLayoutV1,
		"0.1.9": vmOverlayTemplateLayoutV1, SupportedBelow: "", "": "", "dev": "",
	} {
		if got := VMOverlayTemplateLayout(version); got != want {
			t.Errorf("VMOverlayTemplateLayout(%q) = %q, want %q", version, got, want)
		}
	}
}

// The stat of dc-ent-mac's template (GAP-0007): upper/ was the account's.
func TestParseDebugfsStat(t *testing.T) {
	got, ok := parseDebugfsStat([]byte("debugfs 1.47.1 (20-May-2024)\nInode: 14   Type: directory    Mode:  0755   Flags: 0x80000\n" +
		"Generation: 0    Version: 0x00000000:00000000\nUser:   503   Group:    20   Project:     0   Size: 4096\n"))
	if !ok || got != (debugfsInode{dir: true, mode: 0o755, uid: 503, gid: 20}) {
		t.Fatalf("parse = %+v, %v", got, ok)
	}
	for name, out := range map[string]string{
		"not found": "stat: File not found by ext2_lookup while doing stat\n",
		"two":       strings.Repeat("Inode: 14   Type: directory    Mode:  0755   Flags: 0x0\nUser:     0   Group:     0   Size: 1\n", 2),
		"no owner":  "Inode: 14   Type: directory    Mode:  0755   Flags: 0x0\n",
		"empty":     "",
	} {
		if got, ok := parseDebugfsStat([]byte(out)); ok {
			t.Errorf("%s: parsed %+v", name, got)
		}
	}
	if got, ok := parseDebugfsStat([]byte("Inode: 12   Type: regular    Mode:  0644   Flags: 0x0\nUser:     0   Group:     0   Size: 1\n")); !ok || got.dir {
		t.Fatalf("a file parsed as %+v, %v", got, ok)
	}
}

func TestVMOverlayTemplateEnsure(t *testing.T) {
	const mib = 1
	size := int64(mib << 20)
	setup := func(t *testing.T) (*fakeE2fs, VMOverlayTemplate, string) {
		fake := &fakeE2fs{t: t}
		cache := t.TempDir()
		dir := toolsDir(t)
		tpl := VMOverlayTemplate{Cache: cache, Layout: vmOverlayTemplateLayoutV1, OverlayDiskMiB: mib,
			Tools: func() (string, error) { return dir, nil }, Runner: fake}
		return fake, tpl, VMOverlayTemplatePath(cache, vmOverlayTemplateLayoutV1, uint64(size))
	}
	rootOwnedAt := func(t *testing.T, fake *fakeE2fs, path string) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil || info.Size() != size || info.Mode().Perm() != 0o644 {
			t.Fatalf("template %s: %v, %v", path, info, err)
		}
		for _, name := range vmOverlayDirs {
			if ino := fake.read(path)[name]; ino != (fakeInode{Mode: 0o755}) {
				t.Fatalf("%s = %+v, want 0:0 0755", name, ino)
			}
		}
		entries, _ := os.ReadDir(filepath.Dir(path))
		if len(entries) != 1 {
			t.Fatalf("left behind: %v", entries)
		}
	}

	t.Run("the driver's template of the account is replaced", func(t *testing.T) {
		fake, tpl, path := setup(t)
		fake.writeImage(path, size, 503, 20)
		if wrote, err := tpl.Ensure(t.Context()); err != nil || !wrote {
			t.Fatalf("Ensure = %v, %v", wrote, err)
		}
		if !slices.Contains(fake.mkfsArgs, "root_owner=0:0") || fake.formats != 1 || fake.writes != 1 {
			t.Fatalf("mke2fs %q, formats %d, writes %d", fake.mkfsArgs, fake.formats, fake.writes)
		}
		rootOwnedAt(t, fake, path)
		// A second create reads it and writes nothing.
		if wrote, err := tpl.Ensure(t.Context()); err != nil || wrote || fake.formats != 1 {
			t.Fatalf("second Ensure = %v, %v (formats %d)", wrote, err, fake.formats)
		}
	})
	t.Run("a missing template is made", func(t *testing.T) {
		fake, tpl, path := setup(t)
		if wrote, err := tpl.Ensure(t.Context()); err != nil || !wrote {
			t.Fatalf("Ensure = %v, %v", wrote, err)
		}
		rootOwnedAt(t, fake, path)
	})
	t.Run("a root gateway's template is left alone", func(t *testing.T) {
		fake, tpl, path := setup(t)
		fake.writeImage(path, size, 0, 0)
		if wrote, err := tpl.Ensure(t.Context()); err != nil || wrote || fake.formats != 0 {
			t.Fatalf("Ensure = %v, %v (formats %d)", wrote, err, fake.formats)
		}
	})
	t.Run("a template of another size is replaced", func(t *testing.T) {
		fake, tpl, path := setup(t)
		fake.writeImage(path, size/2, 0, 0)
		if wrote, err := tpl.Ensure(t.Context()); err != nil || !wrote {
			t.Fatalf("Ensure = %v, %v", wrote, err)
		}
		rootOwnedAt(t, fake, path)
	})
	t.Run("a group-writable folder is replaced", func(t *testing.T) {
		fake, tpl, path := setup(t)
		fake.writeImage(path, size, 0, 0)
		table := fake.read(path)
		table["work"] = fakeInode{Mode: 0o775}
		fake.write(path, table)
		if wrote, err := tpl.Ensure(t.Context()); err != nil || !wrote {
			t.Fatalf("Ensure = %v, %v", wrote, err)
		}
		rootOwnedAt(t, fake, path)
	})
	t.Run("a template that does not read back root-owned is not published", func(t *testing.T) {
		fake, tpl, path := setup(t)
		fake.writeImage(path, size, 503, 20)
		fake.brokenSi = true
		_, err := tpl.Ensure(t.Context())
		if !errors.Is(err, ErrVMOverlayTemplate) || !strings.Contains(err.Error(), "owned by 503:20, not 0:0") {
			t.Fatalf("Ensure = %v", err)
		}
		if ino := fake.read(path)["upper"]; ino.UID != 503 {
			t.Fatalf("the driver's template was changed: %+v", ino)
		}
		if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
			t.Fatalf("left behind: %v", entries)
		}
	})
	t.Run("no e2fsprogs", func(t *testing.T) {
		_, tpl, _ := setup(t)
		tpl.Tools = func() (string, error) { return t.TempDir(), nil }
		if _, err := tpl.Ensure(t.Context()); !errors.Is(err, ErrVMOverlayTemplate) || !strings.Contains(err.Error(), "mke2fs and debugfs") {
			t.Fatalf("Ensure = %v", err)
		}
		tpl.Tools = func() (string, error) { return "", errors.New("e2fsprogs is not installed") }
		if _, err := tpl.Ensure(t.Context()); !errors.Is(err, ErrVMOverlayTemplate) {
			t.Fatalf("Ensure = %v", err)
		}
	})
	t.Run("an unknown layout is the driver's", func(t *testing.T) {
		fake, tpl, _ := setup(t)
		tpl.Layout = ""
		tpl.Tools = nil
		if wrote, err := tpl.Ensure(t.Context()); err != nil || wrote || fake.formats != 0 {
			t.Fatalf("Ensure = %v, %v", wrote, err)
		}
	})
}

// With the real e2fsprogs where it is installed (Linux CI, the build box):
// the template DefenseClaw makes reads back root-owned with the driver's
// own debugfs, and the account's template is replaced.
func TestVMOverlayTemplateWithRealE2fsprogs(t *testing.T) {
	dir := e2fsprogsIn(append(slices.Clone(linuxE2fsprogsDirs), e2fsprogsDirs...))
	if dir == "" {
		mkfs, err1 := exec.LookPath("mke2fs")
		_, err2 := exec.LookPath("debugfs")
		if err1 != nil || err2 != nil {
			t.Skip("e2fsprogs is not installed")
		}
		dir = filepath.Dir(mkfs)
	}
	cache := t.TempDir()
	tpl := VMOverlayTemplate{Cache: cache, Layout: vmOverlayTemplateLayoutV1, OverlayDiskMiB: 8, Tools: func() (string, error) { return dir, nil }}
	path := VMOverlayTemplatePath(cache, vmOverlayTemplateLayoutV1, 8<<20)

	// The driver's template, as OpenShell 0.1.6 makes it (mke2fs -d from
	// folders of the account).
	staging := t.TempDir()
	for _, name := range vmOverlayDirs {
		must(t, os.Mkdir(filepath.Join(staging, name), 0o755))
	}
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, nil, 0o644))
	must(t, os.Truncate(path, 8<<20))
	mkfs := filepath.Join(dir, "mke2fs")
	if !executable(mkfs) {
		mkfs = filepath.Join(dir, "mkfs.ext4")
	}
	if out, err := exec.Command(mkfs, "-q", "-F", "-t", "ext4", "-E", "root_owner=0:0", "-d", staging, path).CombinedOutput(); err != nil {
		t.Skipf("this mke2fs cannot populate an image (%v): %s", err, out)
	}
	tools, err := tpl.tools()
	must(t, err)
	if err := tpl.rootOwned(t.Context(), tools, path); os.Getuid() != 0 && err == nil {
		t.Fatal("the account's template read back root-owned")
	}

	if _, err := tpl.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := tpl.rootOwned(t.Context(), tools, path); err != nil {
		t.Fatalf("the new template: %v", err)
	}
	if wrote, err := tpl.Ensure(t.Context()); err != nil || wrote {
		t.Fatalf("second Ensure = %v, %v", wrote, err)
	}
	if out, err := exec.Command(filepath.Join(dir, "debugfs"), "-R", "ls -l /", path).CombinedOutput(); err != nil || !strings.Contains(string(out), "lost+found") {
		t.Fatalf("the new template is no ext4 image the driver can use: %v: %s", err, out)
	}
}
