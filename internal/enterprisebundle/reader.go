// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// maxTrailingZeros bounds the zero padding archivers add after the end of a
// tar archive (a 10 KiB record for GNU tar).
const maxTrailingZeros = 1 << 20

// Bundle is the content of a bundle archive or directory, read and checked
// against the reader limits. Nothing in it is trusted yet: the manifest is
// undecoded and no hash or signature has been checked.
type Bundle struct {
	// Manifest is manifest.json as read, nil when absent (a bundle sign
	// input has none yet).
	Manifest []byte
	// Signature is manifest.sig as read, nil when absent.
	Signature []byte
	// Files are every other regular file, keyed by slash-separated path.
	Files map[string][]byte
}

// Paths returns the paths of b.Files, sorted.
func (b *Bundle) Paths() []string {
	paths := make([]string, 0, len(b.Files))
	for name := range b.Files {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	return paths
}

// collector applies the limits shared by both readers: one namespace for
// files and directories, no duplicates, no case-fold collisions, no file
// below a file, the entry count and the expanded size.
type collector struct {
	bundle   *Bundle
	names    map[string]bool // path -> is a directory
	folded   map[string]string
	entries  int
	expanded int64
}

func newCollector() *collector {
	return &collector{
		bundle: &Bundle{Files: map[string][]byte{}},
		names:  map[string]bool{},
		folded: map[string]string{},
	}
}

func (c *collector) claim(name string, dir bool) *Error {
	if err := checkBundlePath(name, dir); err != nil {
		return err
	}
	if c.entries++; c.entries > MaxEntries {
		return refuse(CodeArchiveInvalid, "", "more than %d entries", MaxEntries)
	}
	if _, seen := c.names[name]; seen {
		return refuse(CodeArchiveInvalid, name, "duplicate entry")
	}
	// Every name and every directory above it must fold to itself only: on
	// a case-insensitive file system policies/guardrail/P and
	// policies/guardrail/p are one directory, so the policy would differ by
	// platform.
	for prefix := name; prefix != "."; prefix = path.Dir(prefix) {
		if other, seen := c.folded[strings.ToLower(prefix)]; seen && other != prefix {
			return refuse(CodeArchiveInvalid, name, "differs from %s only in case", safePath(other))
		}
	}
	for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
		if isDir, seen := c.names[parent]; seen && !isDir {
			return refuse(CodeArchiveInvalid, name, "a file is listed below the file %s", safePath(parent))
		}
	}
	if !dir {
		// The parent check above catches a file below an earlier file; this
		// catches a file named like an earlier entry's directory.
		for other := range c.names {
			if strings.HasPrefix(other, name+"/") {
				return refuse(CodeArchiveInvalid, name, "a file has the name of a directory")
			}
		}
	}
	c.names[name] = dir
	for prefix := name; prefix != "."; prefix = path.Dir(prefix) {
		c.folded[strings.ToLower(prefix)] = prefix
	}
	return nil
}

func (c *collector) budget() int64 { return MaxExpandedBytes - c.expanded }

func (c *collector) add(name string, data []byte) *Error {
	c.expanded += int64(len(data))
	if c.expanded > MaxExpandedBytes {
		return refuse(CodeArchiveInvalid, "", "expands to more than %d bytes", MaxExpandedBytes)
	}
	switch name {
	case ManifestName:
		if len(data) > MaxManifestBytes {
			return refuse(CodeManifestInvalid, name, "larger than %d bytes", MaxManifestBytes)
		}
		c.bundle.Manifest = data
	case SignatureName:
		if len(data) > MaxSignatureBytes {
			return refuse(CodeArchiveInvalid, name, "larger than %d bytes", MaxSignatureBytes)
		}
		c.bundle.Signature = data
	default:
		if executableContent(data) {
			return refuse(CodeArchiveInvalid, name, "is a program; bundles carry data only")
		}
		c.bundle.Files[name] = data
	}
	return nil
}

// ReadArchive reads a .dcbundle file (tar inside gzip) from r. It refuses
// (archive_invalid) more than MaxCompressedBytes of input, more than
// MaxExpandedBytes of content or MaxEntries entries, anything but regular
// files and directories, executable files, names outside the bundle tree or
// that could alias another (traversal, case-fold collisions, duplicates),
// and data after the archive.
func ReadArchive(r io.Reader) (*Bundle, error) {
	compressed, err := io.ReadAll(io.LimitReader(r, MaxCompressedBytes+1))
	if err != nil {
		return nil, refuse(CodeArchiveInvalid, "", "read: %v", err)
	}
	if len(compressed) > MaxCompressedBytes {
		return nil, refuse(CodeArchiveInvalid, "", "larger than %d bytes", MaxCompressedBytes)
	}
	src := bytes.NewReader(compressed)
	gz, err := gzip.NewReader(src)
	if err != nil {
		return nil, refuse(CodeArchiveInvalid, "", "not a gzip stream")
	}
	gz.Multistream(false)
	c := newCollector()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, refuse(CodeArchiveInvalid, "", "not a valid tar archive")
		}
		if bundleErr := c.archiveEntry(tr, hdr); bundleErr != nil {
			return nil, bundleErr
		}
	}
	// The end-of-archive blocks are zeros; anything else, in this gzip
	// member or after it, is data the reader would not see.
	rest, err := io.ReadAll(io.LimitReader(gz, maxTrailingZeros+1))
	if err != nil || len(rest) > maxTrailingZeros || bytes.ContainsFunc(rest, func(r rune) bool { return r != 0 }) {
		return nil, refuse(CodeArchiveInvalid, "", "data after the end of the archive")
	}
	if src.Len() != 0 {
		return nil, refuse(CodeArchiveInvalid, "", "data after the end of the gzip stream")
	}
	return c.bundle, nil
}

func (c *collector) archiveEntry(tr *tar.Reader, hdr *tar.Header) *Error {
	name := hdr.Name
	dir := false
	switch hdr.Typeflag {
	case tar.TypeDir:
		dir = true
		name = strings.TrimSuffix(name, "/")
	case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // old archivers still write TypeRegA
	default:
		return refuse(CodeArchiveInvalid, name, "not a regular file or directory")
	}
	if hdr.Linkname != "" {
		return refuse(CodeArchiveInvalid, name, "carries a link target")
	}
	for key := range hdr.PAXRecords {
		if strings.HasPrefix(key, "GNU.sparse.") {
			return refuse(CodeArchiveInvalid, name, "sparse file")
		}
	}
	if !dir && hdr.Mode&0o111 != 0 {
		return refuse(CodeArchiveInvalid, name, "executable file; bundles carry data only")
	}
	if bundleErr := c.claim(name, dir); bundleErr != nil {
		return bundleErr
	}
	if dir {
		if hdr.Size != 0 {
			return refuse(CodeArchiveInvalid, name, "directory with content")
		}
		return nil
	}
	if hdr.Size < 0 || hdr.Size > c.budget() {
		return refuse(CodeArchiveInvalid, "", "expands to more than %d bytes", MaxExpandedBytes)
	}
	data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
	if err != nil || int64(len(data)) != hdr.Size {
		return refuse(CodeArchiveInvalid, name, "truncated entry")
	}
	return c.add(name, data)
}

// ReadDir reads a bundle directory at root with the limits of ReadArchive.
// Links (symbolic links, junctions), devices, sockets and pipes are refused,
// and a file replaced while it is read is refused too; nothing is followed.
func ReadDir(root string) (*Bundle, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, refuse(CodeArchiveInvalid, "", "bundle directory: %v", errors.Unwrap(err))
	}
	if info.Mode().Type() != fs.ModeDir {
		return nil, refuse(CodeArchiveInvalid, "", "bundle path is not a directory")
	}
	c := newCollector()
	if bundleErr := c.walk(root, ""); bundleErr != nil {
		return nil, bundleErr
	}
	return c.bundle, nil
}

func (c *collector) walk(root, rel string) *Error {
	entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return refuse(CodeArchiveInvalid, rel, "unreadable directory")
	}
	for _, entry := range entries {
		name := entry.Name()
		if rel != "" {
			name = rel + "/" + name
		}
		full := filepath.Join(root, filepath.FromSlash(name))
		info, err := os.Lstat(full)
		if err != nil {
			return refuse(CodeArchiveInvalid, name, "unreadable entry")
		}
		switch info.Mode().Type() {
		case fs.ModeDir:
			if bundleErr := c.claim(name, true); bundleErr != nil {
				return bundleErr
			}
			if bundleErr := c.walk(root, name); bundleErr != nil {
				return bundleErr
			}
		case 0:
			if bundleErr := c.claim(name, false); bundleErr != nil {
				return bundleErr
			}
			data, bundleErr := c.readFile(full, name, info)
			if bundleErr != nil {
				return bundleErr
			}
			if bundleErr := c.add(name, data); bundleErr != nil {
				return bundleErr
			}
		default:
			return refuse(CodeArchiveInvalid, name, "not a regular file or directory")
		}
	}
	return nil
}

func (c *collector) readFile(full, name string, info fs.FileInfo) ([]byte, *Error) {
	if info.Size() > c.budget() {
		return nil, refuse(CodeArchiveInvalid, "", "expands to more than %d bytes", MaxExpandedBytes)
	}
	f, err := os.Open(full) // #nosec G304 -- a bundle file, checked against the Lstat result below.
	if err != nil {
		return nil, refuse(CodeArchiveInvalid, name, "unreadable file")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Mode().Type() != 0 {
		return nil, refuse(CodeArchiveInvalid, name, "replaced while it was read")
	}
	data, err := io.ReadAll(io.LimitReader(f, info.Size()+1))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, refuse(CodeArchiveInvalid, name, "changed while it was read")
	}
	return data, nil
}
