// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FS is the filesystem the compiler and the install resolver read. The
// production implementation is the operating system's; tests substitute an
// in-memory tree so golden policies contain fixed paths.
type FS interface {
	EvalSymlinks(path string) (string, error)
	Lstat(path string) (fs.FileInfo, error)
	Stat(path string) (fs.FileInfo, error)
	ReadDir(path string) ([]fs.DirEntry, error)
	Glob(pattern string) ([]string, error)
	// IsELF reports whether path is a regular file that starts with the ELF
	// magic: the agent itself, not a script that starts it.
	IsELF(path string) bool
	// Trusted reports whether every element of path, resolved as the kernel
	// would, is owned by root or uid and not writable by anyone else, so no
	// other account can change what path names.
	Trusted(path string, uid int) bool
}

// OSFS is the real filesystem.
func OSFS() FS { return osFS{} }

type osFS struct{}

func (osFS) EvalSymlinks(p string) (string, error)   { return filepath.EvalSymlinks(p) }
func (osFS) Lstat(p string) (fs.FileInfo, error)     { return os.Lstat(p) }
func (osFS) Stat(p string) (fs.FileInfo, error)      { return os.Stat(p) }
func (osFS) ReadDir(p string) ([]fs.DirEntry, error) { return os.ReadDir(p) }
func (osFS) Glob(p string) ([]string, error)         { return filepath.Glob(p) }

func (osFS) IsELF(p string) bool {
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	file, err := os.Open(p)
	if err != nil {
		return false
	}
	defer file.Close()
	var magic [4]byte
	if n, _ := file.Read(magic[:]); n != 4 {
		return false
	}
	return magic == [4]byte{0x7f, 'E', 'L', 'F'}
}

func (osFS) Trusted(p string, uid int) bool { return pathTrustedFor(p, uid) }

// inside reports whether path is dir or below it.
func inside(dir, path string) bool {
	dir, path = filepath.Clean(dir), filepath.Clean(path)
	if path == dir {
		return true
	}
	return strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}
