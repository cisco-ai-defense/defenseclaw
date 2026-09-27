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

package packs

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	sandboxpolicies "github.com/defenseclaw/defenseclaw/policies/sandbox"
)

// maxCustomPacks bounds how many entries of a pack directory List inspects.
const maxCustomPacks = 256

// userHomeDir, validateTrustedFile, currentUID and fileOwner are swapped in
// tests.
var (
	userHomeDir         = os.UserHomeDir
	validateTrustedFile = managed.ValidateTrustedFilePath
	currentUID          = os.Getuid
	fileOwner           = statOwner
)

// BuiltinNames lists the built-in packs from loosest to strictest.
func BuiltinNames() []string {
	return sandboxpolicies.BuiltinPackNames()
}

// IsBuiltin reports whether name is a built-in pack. Custom packs may not
// reuse these names.
func IsBuiltin(name string) bool {
	for _, builtin := range BuiltinNames() {
		if name == builtin {
			return true
		}
	}
	return false
}

// Builtin loads an embedded pack.
func Builtin(name string) (*Pack, error) {
	if !IsBuiltin(name) {
		return nil, packErr(name, "", "not_found", "no built-in pack named %q (built-in packs: %s)",
			name, strings.Join(BuiltinNames(), ", "))
	}
	data, err := fs.ReadFile(sandboxpolicies.BuiltinPacks(), path.Join(name, PackFileName))
	if err != nil {
		return nil, packErr("builtin:"+name, "", "unreadable", "embedded pack is unavailable")
	}
	pack, err := Parse(data, "builtin:"+name)
	if err != nil {
		return nil, err
	}
	if pack.Name != name {
		return nil, packErr(pack.Source, "name", "name_mismatch", "%q does not match the pack directory %q", pack.Name, name)
	}
	pack.Builtin = true
	return pack, nil
}

// Load resolves a pack reference:
//   - "" selects DefaultPack;
//   - a built-in name (open, balanced, strict) selects the embedded pack;
//   - any other pack name selects <packDir>/<name>/pack.yaml;
//   - an absolute path (or "~/…") selects that pack.yaml or pack directory.
//
// Built-in names always resolve to the embedded packs, so a custom file can
// never impersonate one.
func Load(ref, packDir string) (*Pack, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		ref = DefaultPack
	}
	if IsBuiltin(ref) {
		return Builtin(ref)
	}
	if packNamePattern.MatchString(ref) {
		return loadNamed(ref, packDir)
	}
	return LoadFile(ref)
}

// LoadTrusted is Load for a pack an administrator relies on (a
// managed_enterprise openshell.admin.required_pack): before a custom pack is
// read, its file and every directory above it must be administrator-owned and
// not writable by other users (managed.ValidateTrustedFilePath), so a user
// cannot swap the pack the administrator-owned config.yaml names. Built-in
// packs are embedded and always trusted.
func LoadTrusted(ref, packDir string) (*Pack, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || IsBuiltin(ref) {
		return Load(ref, packDir)
	}
	file, err := packFilePath(ref, packDir)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(file); errors.Is(err, fs.ErrNotExist) {
		return nil, packErr(file, "", "not_found", "no such pack file")
	}
	if err := validateTrustedFile(file, "sandbox policy pack"); err != nil {
		return nil, packErr(file, "", "untrusted",
			"must be an administrator-owned file that other users cannot modify (%v)", err)
	}
	pack, err := Load(ref, packDir)
	if err != nil {
		return nil, err
	}
	if pack.Source != file {
		return nil, packErr(file, "", "untrusted", "loaded %s instead of the checked file", pack.Source)
	}
	return pack, nil
}

// packFilePath returns the pack.yaml a custom pack reference names, without
// reading it (see Load).
func packFilePath(ref, packDir string) (string, error) {
	var target string
	if packNamePattern.MatchString(ref) {
		packDir = strings.TrimSpace(packDir)
		if packDir == "" {
			return "", packErr(ref, "", "not_found", "no built-in pack named %q and openshell.pack_dir is not set", ref)
		}
		dir, err := expandHome(packDir)
		if err != nil {
			return "", packErr(ref, "", "not_found", "openshell.pack_dir %q: %v", packDir, err)
		}
		target = filepath.Join(dir, ref)
	} else {
		expanded, err := expandHome(ref)
		if err != nil {
			return "", packErr(ref, "", "not_found", "%v", err)
		}
		if !filepath.IsAbs(expanded) {
			return "", packErr(ref, "", "relative_path", "pack paths must be absolute (or start with ~/)")
		}
		target = filepath.Clean(expanded)
	}
	if info, err := os.Lstat(target); err == nil && info.IsDir() {
		target = filepath.Join(target, PackFileName)
	}
	return target, nil
}

func loadNamed(name, packDir string) (*Pack, error) {
	packDir = strings.TrimSpace(packDir)
	if packDir == "" {
		return nil, packErr(name, "", "not_found", "no built-in pack named %q and openshell.pack_dir is not set", name)
	}
	dir, err := expandHome(packDir)
	if err != nil {
		return nil, packErr(name, "", "not_found", "openshell.pack_dir %q: %v", packDir, err)
	}
	candidate := filepath.Join(dir, name)
	if _, err := os.Lstat(candidate); errors.Is(err, fs.ErrNotExist) {
		return nil, packErr(name, "", "not_found", "no built-in or custom pack named %q (custom packs live in %s/<name>/%s)",
			name, dir, PackFileName)
	}
	pack, err := LoadFile(candidate)
	if err != nil {
		return nil, err
	}
	if pack.Name != name {
		return nil, packErr(pack.Source, "name", "name_mismatch", "%q does not match the pack directory %q", pack.Name, name)
	}
	return pack, nil
}

// LoadFile loads a custom pack from an absolute path to a pack.yaml or to the
// directory holding one ("~/" expands to the home directory). The pack
// directory and the file must not be symbolic links, the file must be a
// regular file of at most MaxPackBytes, no other local user may have written
// it or be able to replace it (checkPackOwnership), and the pack may not
// claim a built-in name.
func LoadFile(p string) (*Pack, error) {
	raw := strings.TrimSpace(p)
	expanded, err := expandHome(raw)
	if err != nil {
		return nil, packErr(raw, "", "not_found", "%v", err)
	}
	if !filepath.IsAbs(expanded) {
		return nil, packErr(raw, "", "relative_path", "pack paths must be absolute (or start with ~/)")
	}
	target := filepath.Clean(expanded)
	info, err := os.Lstat(target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, packErr(target, "", "not_found", "no such pack file or directory")
		}
		return nil, packErr(target, "", "unreadable", "cannot inspect the pack path")
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, packErr(target, "", "symlink", "pack paths must not be symbolic links")
	}
	if info.IsDir() {
		target = filepath.Join(target, PackFileName)
		info, err = os.Lstat(target)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, packErr(target, "", "not_found", "the pack directory has no %s", PackFileName)
			}
			return nil, packErr(target, "", "unreadable", "cannot inspect the pack file")
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, packErr(target, "", "symlink", "pack paths must not be symbolic links")
		}
	}
	if !info.Mode().IsRegular() {
		return nil, packErr(target, "", "not_regular", "the pack must be a regular file")
	}
	if info.Size() > MaxPackBytes {
		return nil, packErr(target, "", "too_large", "pack exceeds %d bytes", MaxPackBytes)
	}
	if runtime.GOOS != "windows" {
		if err := checkPackOwnership(target, info); err != nil {
			return nil, err
		}
	}
	data, err := safefile.ReadRegularFileBounded(target, MaxPackBytes)
	if err != nil {
		return nil, packErr(target, "", "unreadable", "cannot read the pack file safely")
	}
	pack, err := Parse(data, target)
	if err != nil {
		return nil, err
	}
	if IsBuiltin(pack.Name) {
		return nil, packErr(target, "name", "reserved_name", "%q is a built-in pack name; custom packs need their own name", pack.Name)
	}
	return pack, nil
}

// checkPackOwnership refuses a pack file that another local user wrote or
// could replace. The file and its directory must be owned by the current
// user or root, and neither may be world-writable, with one exception: a
// root-owned file may sit in a sticky world-writable directory, where no
// other user can replace it. A file of the user's own in such a directory
// (for example under /tmp) is refused, because the directory's contents are
// not the user's to vouch for.
func checkPackOwnership(file string, info fs.FileInfo) error {
	uid := currentUID()
	owner, ok := fileOwner(info)
	switch {
	case !ok:
		return packErr(file, "", "unreadable", "cannot inspect the pack file's owner")
	case owner != uid && owner != 0:
		return packErr(file, "", "foreign_owner",
			"the pack file is owned by another user (uid %d); only packs you or root own are loaded", owner)
	case info.Mode().Perm()&0o002 != 0:
		return packErr(file, "", "world_writable", "the pack file is writable by every user; run chmod o-w on it")
	}
	dir, err := os.Stat(filepath.Dir(file))
	if err != nil {
		return packErr(file, "", "unreadable", "cannot inspect the pack directory")
	}
	dirOwner, ok := fileOwner(dir)
	switch {
	case !ok:
		return packErr(file, "", "unreadable", "cannot inspect the pack directory's owner")
	case dirOwner != uid && dirOwner != 0:
		// The directory's owner can replace any file in it.
		return packErr(file, "", "foreign_owner",
			"the pack directory is owned by another user (uid %d); keep packs in a directory you or root own", dirOwner)
	case dir.Mode().Perm()&0o002 == 0:
		return nil
	case dir.Mode()&fs.ModeSticky == 0:
		return packErr(file, "", "world_writable", "the pack directory is writable by every user; run chmod o-w on it")
	case owner != 0:
		return packErr(file, "", "world_writable",
			"the pack is in a directory every user can write to; move it to a directory only you can write to")
	}
	return nil
}

// Validate strictly loads a pack file for `defenseclaw sandbox pack validate`.
func Validate(p string) (*Pack, error) {
	return LoadFile(p)
}

// Entry describes one pack for `defenseclaw sandbox pack list`.
type Entry struct {
	Name        string `json:"name"`
	Builtin     bool   `json:"builtin"`
	Source      string `json:"source"`
	Description string `json:"description,omitempty"`
	Profile     string `json:"profile,omitempty"`
	Digest      string `json:"digest,omitempty"`
	// Err is set for a custom pack that failed to load; the other fields
	// then describe only where it was found.
	Err error `json:"-"`
}

// List returns the built-in packs followed by the custom packs under packDir
// (sorted by name). A missing packDir lists only the built-ins; directories
// without a pack.yaml (for example the egress feed directory) are skipped.
func List(packDir string) ([]Entry, error) {
	var entries []Entry
	for _, name := range BuiltinNames() {
		pack, err := Builtin(name)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entryFor(pack))
	}
	packDir = strings.TrimSpace(packDir)
	if packDir == "" {
		return entries, nil
	}
	dir, err := expandHome(packDir)
	if err != nil {
		return nil, packErr(packDir, "", "unreadable", "%v", err)
	}
	children, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return entries, nil
		}
		return nil, packErr(dir, "", "unreadable", "cannot read the pack directory")
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
	inspected := 0
	for _, child := range children {
		name := child.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		inspected++
		if inspected > maxCustomPacks {
			return nil, packErr(dir, "", "too_many", "the pack directory has more than %d entries", maxCustomPacks)
		}
		full := filepath.Join(dir, name)
		if child.Type()&fs.ModeSymlink != 0 {
			entries = append(entries, Entry{Name: name, Source: full,
				Err: packErr(full, "", "symlink", "pack paths must not be symbolic links")})
			continue
		}
		if !child.IsDir() {
			continue
		}
		if _, err := os.Lstat(filepath.Join(full, PackFileName)); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if !packNamePattern.MatchString(name) {
			entries = append(entries, Entry{Name: name, Source: full,
				Err: packErr(full, "", "invalid_name", "pack directory names must be lowercase letters, digits and dashes")})
			continue
		}
		if IsBuiltin(name) {
			entries = append(entries, Entry{Name: name, Source: full,
				Err: packErr(full, "", "reserved_name", "%q is a built-in pack name; this directory is ignored", name)})
			continue
		}
		pack, err := loadNamed(name, dir)
		if err != nil {
			entries = append(entries, Entry{Name: name, Source: full, Err: err})
			continue
		}
		entries = append(entries, entryFor(pack))
	}
	return entries, nil
}

func entryFor(p *Pack) Entry {
	return Entry{
		Name:        p.Name,
		Builtin:     p.Builtin,
		Source:      p.Source,
		Description: p.Description,
		Profile:     p.Profile(),
		Digest:      p.Digest,
	}
}

func expandHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := userHomeDir()
	if err != nil || home == "" {
		return "", errors.New("cannot resolve the home directory")
	}
	return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/")), nil
}
