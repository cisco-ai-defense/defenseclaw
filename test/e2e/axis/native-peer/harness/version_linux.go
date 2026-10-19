// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func validateClaudeELF(data []byte, loader bool) error {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return errors.New("fixed Claude ELF unreadable")
	}
	defer f.Close()
	want := elf.ET_EXEC
	if loader {
		want = elf.ET_DYN
	}
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_X86_64 || f.Type != want || len(f.Progs) == 0 || len(f.Progs) > 128 {
		return errors.New("fixed Claude ELF target differs")
	}
	entry, interpreters, dynamic := false, 0, 0
	for _, p := range f.Progs {
		if p.Filesz > p.Memsz || p.Off > uint64(len(data)) || p.Filesz > uint64(len(data))-p.Off || p.Vaddr > ^uint64(0)-p.Memsz || p.Flags&(elf.PF_W|elf.PF_X) == elf.PF_W|elf.PF_X {
			return errors.New("fixed Claude ELF segment differs")
		}
		entry = entry || p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && f.Entry >= p.Vaddr && f.Entry-p.Vaddr < p.Filesz
		if p.Type == elf.PT_INTERP {
			interpreters++
			value, readErr := io.ReadAll(io.LimitReader(p.Open(), 129))
			if loader || p.Filesz > 128 || readErr != nil || string(value) != "/lib/ld-musl-x86_64.so.1\x00" {
				return errors.New("fixed Claude interpreter differs")
			}
		}
		if p.Type == elf.PT_DYNAMIC {
			dynamic++
			if p.Filesz == 0 || p.Filesz%16 != 0 || p.Filesz > 64<<10 {
				return errors.New("fixed Claude dynamic table differs")
			}
			terminated := false
			for at := p.Off; at < p.Off+p.Filesz; at += 16 {
				tag := binary.LittleEndian.Uint64(data[at : at+8])
				if tag == 0 {
					terminated = true
					break
				}
				if tag == uint64(elf.DT_RPATH) || tag == uint64(elf.DT_RUNPATH) || loader && tag == uint64(elf.DT_NEEDED) {
					return errors.New("fixed Claude dynamic dependency/search differs")
				}
			}
			if !terminated {
				return errors.New("fixed Claude dynamic table unterminated")
			}
		}
	}
	if !entry || dynamic != 1 || loader && interpreters != 0 || !loader && interpreters != 1 {
		return errors.New("fixed Claude entry/interpreter missing")
	}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
		values, err := f.DynString(tag)
		if err != nil || len(values) != 0 {
			return errors.New("fixed Claude loader search path refused")
		}
	}
	needed, err := f.ImportedLibraries()
	if err != nil || loader && len(needed) != 0 || !loader && (len(needed) != 1 || needed[0] != "libc.musl-x86_64.so.1") {
		return errors.New("fixed Claude dependency differs")
	}
	return nil
}

// This ordinary private file is deliberately not a memfd: Bubblewrap reopens
// its fixed locator in each cloned mount namespace and compares the held object.
// The host driver proved its creator-mount reachability/no-IDMAP before cloning.
// Here the inherited root and loader must still refer to the same original mount.
func verifyVersionLoader(root, file *os.File) error {
	if root == nil || file == nil || privateDirectory(root) != nil {
		return errors.New("fixed loader root absent")
	}
	var before, after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0500 || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size != claudeLoaderSize {
		return errors.New("fixed loader metadata differs")
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	fdflags, fdErr := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || fdErr != nil || !versionLoaderFlags(flags, fdflags, true) {
		return errors.New("fixed loader descriptor rights differ")
	}
	var sourceFS, rootFS unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &sourceFS) != nil || unix.Fstatfs(int(root.Fd()), &rootFS) != nil || sourceFS.Type != rootFS.Type || sourceFS.Fsid != rootFS.Fsid || sourceFS.Flags&unix.ST_NOEXEC != 0 {
		return errors.New("fixed loader filesystem differs")
	}
	switch sourceFS.Type {
	case unix.EXT4_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC:
	default:
		return errors.New("fixed loader local filesystem unsupported")
	}
	var a, b unix.Statx_t
	if unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &a) != nil || unix.Statx(int(root.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &b) != nil || a.Mask&unix.STATX_MNT_ID == 0 || b.Mask&unix.STATX_MNT_ID == 0 || a.Mnt_id != b.Mnt_id {
		return errors.New("fixed loader held mount differs")
	}
	current, err := openRelative(root, claudeLoaderLeaf, unix.O_RDONLY)
	if err != nil {
		return errors.New("fixed loader entry missing")
	}
	defer current.Close()
	var named unix.Stat_t
	if unix.Fstat(int(current.Fd()), &named) != nil || named.Dev != before.Dev || named.Ino != before.Ino || named.Mode != before.Mode || named.Nlink != 1 || named.Size != before.Size {
		return errors.New("fixed loader entry identity differs")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.NewSectionReader(file, 0, claudeLoaderSize+1))
	if err != nil || n != claudeLoaderSize || hex.EncodeToString(hash.Sum(nil)) != claudeLoaderSHA || unix.Fstat(int(file.Fd()), &after) != nil || !sameLoaderMetadata(before, after) {
		return errors.New("fixed loader bytes or metadata changed")
	}
	return nil
}

func inheritedVersionLoader(root *os.File, fd uintptr) (*os.File, error) {
	f := os.NewFile(fd, "fixed-held-version-loader")
	if _, err := unix.FcntlInt(f.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := verifyVersionLoader(root, f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func sameLoaderMetadata(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func versionLoaderFlags(flags, descriptorFlags int, closeOnExec bool) bool {
	return flags&unix.O_ACCMODE == unix.O_RDONLY && (descriptorFlags&unix.FD_CLOEXEC != 0) == closeOnExec
}
