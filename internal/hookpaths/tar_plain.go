// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"archive/tar"
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Bounds of the tar archive read: a larger archive, or one with more
// members, keeps the opaque extraction scope.
const (
	maxTarPlainBytes   = 64 << 20
	maxTarPlainMembers = 4096
)

// tarArchiveHoldsNoLink reports a static tar extraction whose one archive
// file holds only regular files and directories with relative names and no
// .. component, so it makes no link in its destination
// (rel-1-0-6:GAP-0339): tar -xf plain.tar -C d1 && cp -a d1 e3 && echo k
// >> e3/p writes a plain file. The destination must be known (tarScan),
// the archive word must name a file the command writes nowhere else (its
// base name appears once in the command), and the archive must be plain,
// gzip or bzip2. The hook client reads the archive and records
// TarPlainFactPrefix. A gateway with client evidence reads the archive
// itself where it can and needs the fact as well; where it cannot, the
// fact decides. Anything else keeps the opaque reading.
func tarArchiveHoldsNoLink(program string, args []string, static []bool, cwd, command string, facts map[string]string, record bool) bool {
	if !strings.HasSuffix(program, "tar") || !filepath.IsAbs(cwd) {
		return false
	}
	if _, _, extract, ok := tarScan(args, static, cwd); !ok || !extract {
		return false
	}
	archive, ok := tarArchiveWord(args, static)
	if !ok || archive == "" || archive == "-" || strings.ContainsAny(archive, "*?[$`") ||
		strings.Count(command, filepath.Base(archive)) != 1 {
		return false
	}
	path := OperandPath(archive, cwd)
	key := TarPlainFactPrefix + path
	if !record && facts != nil {
		if _, err := os.Stat(path); err == nil && !tarArchivePlain(path) {
			return false
		}
		return facts[key] == "1"
	}
	plain := tarArchivePlain(path)
	if record && facts != nil && plain {
		facts[key] = "1"
	}
	return plain
}

// tarArchiveWord returns the one archive operand of a tar call: -f FILE,
// -fFILE, a cluster ending in f followed by FILE, --file FILE, --file=FILE,
// or an old-style cluster (xf FILE). ok is false for none or more than one.
func tarArchiveWord(args []string, static []bool) (string, bool) {
	archive, found := "", 0
	take := func(value string) {
		archive = value
		found++
	}
	for i := 0; i < len(args); i++ {
		if !static[i] {
			return "", false
		}
		arg := args[i]
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "--") {
			name, value, joined := strings.Cut(arg[2:], "=")
			if option, unique := longOption(name, tarLongOptions); unique && option == "file" {
				if !joined {
					if i++; i >= len(args) {
						return "", false
					}
					value = args[i]
				}
				take(value)
			}
			continue
		}
		oldStyle := i == 0 && !strings.HasPrefix(arg, "-")
		if !oldStyle && !strings.HasPrefix(arg, "-") {
			continue
		}
		cluster := strings.TrimPrefix(arg, "-")
		for j := 0; j < len(cluster); j++ {
			switch cluster[j] {
			case 'f':
				value := cluster[j+1:]
				if oldStyle || value == "" {
					if i++; i >= len(args) {
						return "", false
					}
					value = args[i]
				}
				take(value)
				j = len(cluster)
			case 'C', 'T', 'X', 'b', 'N', 'V', 'H', 'K', 'L':
				if oldStyle || j+1 == len(cluster) {
					i++
				}
				j = len(cluster)
			}
		}
	}
	return archive, found == 1
}

// tarArchivePlain reads the archive at path and reports that every member
// is a regular file or a directory with a relative name and no ..
// component, within the bounds.
func tarArchivePlain(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxTarPlainBytes {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	buffered := bufio.NewReader(io.LimitReader(file, maxTarPlainBytes))
	magic, _ := buffered.Peek(3)
	var stream io.Reader = buffered
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		zipped, err := gzip.NewReader(buffered)
		if err != nil {
			return false
		}
		defer zipped.Close()
		stream = io.LimitReader(zipped, 4*maxTarPlainBytes)
	case len(magic) == 3 && string(magic) == "BZh":
		stream = io.LimitReader(bzip2.NewReader(buffered), 4*maxTarPlainBytes)
	}
	reader := tar.NewReader(stream)
	members := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return members > 0
		}
		if err != nil {
			return false
		}
		if members++; members > maxTarPlainMembers {
			return false
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		default:
			return false
		}
		name := filepath.ToSlash(header.Name)
		if name == "" || strings.HasPrefix(name, "/") || filepath.IsAbs(header.Name) || strings.Contains(name, "\\") {
			return false
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return false
			}
		}
	}
}
