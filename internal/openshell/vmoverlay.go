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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The MicroVM overlay template (GAP-0007 on macOS, GAP-0570 on Linux).
//
// OpenShell's MicroVM driver gives every sandbox a writable overlay disk,
// cloned from one template per overlay size in its image cache:
// images/overlay-templates/<layout>/<bytes>.ext4. The guest's root folder
// is that disk's upper directory. OpenShell 0.1.5 to 0.1.7-pre (and
// upstream main) formats the template from upper/, work/ and config/
// folders it creates as the gateway's own account, and mke2fs keeps their
// owner: on every gateway that does not run as root (per-user, and the
// managed gateway, which runs as the enrolled account on macOS and Linux)
// the guest's / belongs to that account, which is also the workload's
// uid. DefenseClaw's workload check (manager/verify.go, trusted_resolver)
// trusts the guest's localhost resolver only on a root-owned path from /,
// so it refused every such MicroVM create ("the MicroVM could not resolve
// localhost to its loopback ingress").
//
// The check is right: a workload that owns / could swap /etc or /usr. So
// DefenseClaw does not relax it. Before a MicroVM create it makes the
// template what the driver makes when it runs as root: the same empty ext4
// image, with upper/, work/ and config/ owned by 0:0. Formatting an image
// file needs no privilege, so this works for any account. The driver
// reuses a template of the right size as it is (it checks only the size),
// clones it for each new sandbox, and writes its own files into upper/ as
// before. The guest check still decides: a template changed back to the
// account's owner is refused as before, never trusted.

// vmOverlayTemplateDir is the image cache folder of the overlay templates.
const vmOverlayTemplateDir = "overlay-templates"

// vmOverlayTemplateLayoutV1 is the template layout of OpenShell 0.1.5 up
// to the next minor release (OVERLAY_TEMPLATE_CACHE_LAYOUT_VERSION).
const vmOverlayTemplateLayoutV1 = "sandbox-overlay-ext4-v1"

// vmOverlayDirs are the folders of a template's root: the overlay's upper
// and work directories and the driver's config folder.
var vmOverlayDirs = []string{"upper", "work", "config"}

// VMOverlayTemplateLayout is the overlay template layout of the MicroVM
// driver of OpenShell release version, "" for a release whose layout
// DefenseClaw does not know (it then leaves the templates to the driver).
func VMOverlayTemplateLayout(version string) string {
	v, err := ParseVersion(version)
	if err != nil {
		return ""
	}
	low, _ := ParseVersion("0.1.5")
	high, _ := ParseVersion(SupportedBelow)
	if v.Compare(low) < 0 || v.Compare(high) >= 0 {
		return ""
	}
	return vmOverlayTemplateLayoutV1
}

// VMOverlayTemplatePath is the template of overlays of sizeBytes in the
// driver's image cache (VMImageCache) for layout.
func VMOverlayTemplatePath(cache, layout string, sizeBytes uint64) string {
	return filepath.Join(cache, vmOverlayTemplateDir, layout, strconv.FormatUint(sizeBytes, 10)+".ext4")
}

// VMOverlayTemplate prepares the root-owned overlay template of one
// MicroVM gateway.
type VMOverlayTemplate struct {
	// Cache is the driver's image cache (VMImageCache).
	Cache string
	// Layout is the driver's template layout (VMOverlayTemplateLayout).
	Layout string
	// OverlayDiskMiB is the gateway's overlay size (VMConfig.Resources).
	OverlayDiskMiB int64
	// Tools finds the folder that holds mke2fs (or mkfs.ext4) and
	// debugfs, the e2fsprogs the driver formats its disks with
	// (VMDriverE2fsprogs).
	Tools func() (string, error)
	// Runner runs mke2fs and debugfs; nil runs them with ExecRunner.
	Runner Runner
}

// ErrVMOverlayTemplate wraps why the template could not be prepared.
var ErrVMOverlayTemplate = errors.New("DefenseClaw could not prepare the MicroVM overlay template with a root-owned root folder")

// Ensure makes the template root-owned. It reports whether it wrote one:
// false when the template already has root-owned folders (also the
// template of a gateway that runs as root). A template of another owner
// is replaced atomically, a new image renamed over it, so a clone in
// progress reads the old one or the new one.
func (t VMOverlayTemplate) Ensure(ctx context.Context) (bool, error) {
	if t.Cache == "" || t.Layout == "" {
		return false, nil
	}
	mib := t.OverlayDiskMiB
	if mib <= 0 {
		mib = DefaultVMOverlayDiskMiB
	}
	size := uint64(mib) << 20
	path := VMOverlayTemplatePath(t.Cache, t.Layout, size)
	tools, err := t.tools()
	if err != nil {
		return false, err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && uint64(info.Size()) == size {
		if t.rootOwned(ctx, tools, path) == nil {
			return false, nil
		}
	}
	if err := t.build(ctx, tools, path, size); err != nil {
		return false, fmt.Errorf("%w (%s): %v", ErrVMOverlayTemplate, path, err)
	}
	return true, nil
}

// e2fsTools is the e2fsprogs a template is read and made with.
type e2fsTools struct{ mke2fs, debugfs string }

func (t VMOverlayTemplate) tools() (e2fsTools, error) {
	if t.Tools == nil {
		return e2fsTools{}, fmt.Errorf("%w: no e2fsprogs folder is known", ErrVMOverlayTemplate)
	}
	dir, err := t.Tools()
	if err != nil {
		return e2fsTools{}, fmt.Errorf("%w: %v", ErrVMOverlayTemplate, err)
	}
	if dir == "" || !hasE2fsprogs(dir) {
		return e2fsTools{}, fmt.Errorf("%w: no folder holds e2fsprogs' mke2fs and debugfs", ErrVMOverlayTemplate)
	}
	mkfs := filepath.Join(dir, "mke2fs")
	if !executable(mkfs) {
		mkfs = filepath.Join(dir, "mkfs.ext4")
	}
	return e2fsTools{mke2fs: mkfs, debugfs: filepath.Join(dir, "debugfs")}, nil
}

func (t VMOverlayTemplate) runner() Runner {
	if t.Runner != nil {
		return t.Runner
	}
	return ExecRunner{}
}

// vmOverlayToolTimeout bounds one mke2fs or debugfs run on the template.
const vmOverlayToolTimeout = 2 * time.Minute

// build formats a new template next to path and renames it over path.
func (t VMOverlayTemplate) build(ctx context.Context, tools e2fsTools, path string, size uint64) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".defenseclaw-overlay-*.ext4")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	// A sparse file of the overlay's size, as the driver makes it.
	if err := f.Truncate(int64(size)); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	run := t.runner()
	if out, err := run.Output(ctx, Command{Name: tools.mke2fs, Args: []string{"-q", "-F", "-t", "ext4", "-E", "root_owner=0:0", tmp},
		Timeout: vmOverlayToolTimeout}); err != nil {
		return fmt.Errorf("mke2fs: %v: %s", err, truncateToolOutput(out))
	}
	var script strings.Builder
	for _, name := range vmOverlayDirs {
		fmt.Fprintf(&script, "mkdir %s\nsif %[1]s uid 0\nsif %[1]s gid 0\nsif %[1]s mode 040755\n", name)
	}
	cmds, err := os.CreateTemp(dir, ".defenseclaw-overlay-*.debugfs")
	if err != nil {
		return err
	}
	defer os.Remove(cmds.Name())
	if _, err := cmds.WriteString(script.String()); err != nil {
		_ = cmds.Close()
		return err
	}
	if err := cmds.Close(); err != nil {
		return err
	}
	if out, err := run.Output(ctx, Command{Name: tools.debugfs, Args: []string{"-w", "-f", cmds.Name(), tmp},
		Timeout: vmOverlayToolTimeout}); err != nil {
		return fmt.Errorf("debugfs: %v: %s", err, truncateToolOutput(out))
	}
	// Read the result back: only a template whose folders are 0:0 0755
	// is published.
	if err := t.rootOwned(ctx, tools, tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// rootOwned checks, with debugfs reading the image, that each of the
// template's folders is a directory owned by 0:0 with mode 0755.
func (t VMOverlayTemplate) rootOwned(ctx context.Context, tools e2fsTools, image string) error {
	run := t.runner()
	for _, name := range vmOverlayDirs {
		out, err := run.Output(ctx, Command{Name: tools.debugfs, Args: []string{"-R", "stat " + name, image}, Timeout: vmOverlayToolTimeout})
		if err != nil {
			return fmt.Errorf("debugfs stat %s: %v: %s", name, err, truncateToolOutput(out))
		}
		ino, ok := parseDebugfsStat(out)
		switch {
		case !ok:
			return fmt.Errorf("the template has no %s folder", name)
		case !ino.dir:
			return fmt.Errorf("the template's %s is not a folder", name)
		case ino.uid != 0 || ino.gid != 0:
			return fmt.Errorf("the template's %s folder is owned by %d:%d, not 0:0", name, ino.uid, ino.gid)
		case ino.mode != 0o755:
			return fmt.Errorf("the template's %s folder has mode %o, not 755", name, ino.mode)
		}
	}
	return nil
}

// debugfsInode is what `debugfs -R "stat NAME"` reports of one inode.
type debugfsInode struct {
	dir      bool
	mode     uint32
	uid, gid int
}

var (
	debugfsTypeRE  = regexp.MustCompile(`(?m)^Inode:\s+\d+\s+Type:\s+(\S+)\s+Mode:\s+([0-7]+)\s`)
	debugfsOwnerRE = regexp.MustCompile(`(?m)^User:\s+(\d+)\s+Group:\s+(\d+)\s`)
)

// parseDebugfsStat reads debugfs's stat of one inode; ok is false unless
// it names exactly one (debugfs prints "File not found" and exits 0).
func parseDebugfsStat(out []byte) (debugfsInode, bool) {
	types, owners := debugfsTypeRE.FindAllSubmatch(out, -1), debugfsOwnerRE.FindAllSubmatch(out, -1)
	if len(types) != 1 || len(owners) != 1 {
		return debugfsInode{}, false
	}
	mode, err1 := strconv.ParseUint(string(types[0][2]), 8, 32)
	uid, err2 := strconv.Atoi(string(owners[0][1]))
	gid, err3 := strconv.Atoi(string(owners[0][2]))
	if err1 != nil || err2 != nil || err3 != nil {
		return debugfsInode{}, false
	}
	return debugfsInode{dir: string(types[0][1]) == "directory", mode: uint32(mode) & 0o7777, uid: uid, gid: gid}, true
}

func truncateToolOutput(out []byte) string {
	s := strings.TrimSpace(string(out))
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

// VMDriverE2fsprogs is the folder of the e2fsprogs the MicroVM driver
// formats its disks with, which DefenseClaw formats the overlay template
// with too. On a managed Mac it is the managed rule's
// (ManagedE2fsprogsToolDir: the administrator's
// enterprise.openshell.e2fsprogs_dir, else the account's own build, else
// the package's; never a Homebrew keg), which the gateway's PATH has
// first; trust is the managed trust check (nil: managed.ValidateTrusted*,
// as the gateway's exec shim and the managed doctor use).
// Elsewhere it is the first of the folders the driver searches (the
// Homebrew kegs on a Mac, the system folders on Linux), else, for a
// per-user gateway, the PATH's.
func VMDriverE2fsprogs(goos string, managedAccount bool, adminDir, home string, trust func(path string, file bool) error) (string, error) {
	if goos == "darwin" && managedAccount {
		if trust == nil {
			trust = (&Doctor{}).trustManagedE2fsprogs
		}
		dir, problem := ManagedE2fsprogsToolDir(adminDir, home, os.Getuid(), trust)
		if dir == "" {
			return "", errors.New(problem)
		}
		return dir, nil
	}
	dirs := e2fsprogsDirs
	if goos == "linux" {
		dirs = linuxE2fsprogsDirs
	}
	if dir := e2fsprogsIn(dirs); dir != "" {
		return dir, nil
	}
	if !managedAccount {
		mkfs, err1 := exec.LookPath("mke2fs")
		_, err2 := exec.LookPath("debugfs")
		if err1 == nil && err2 == nil {
			return filepath.Dir(mkfs), nil
		}
	}
	return "", errors.New("e2fsprogs (mke2fs and debugfs) is not installed where the MicroVM driver finds it")
}
