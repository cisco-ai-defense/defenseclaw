// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"archive/tar"
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Bounds of the tar archive read: 64 MiB of archive file and 64 MiB of
// uncompressed tar stream, and 4096 members. A larger archive keeps the
// opaque extraction scope (review 8 item 3).
const (
	maxTarPlainBytes   = 64 << 20
	maxTarPlainMembers = 4096
)

// errTarPlainBound ends a tar read past maxTarPlainBytes of stream.
var errTarPlainBound = errors.New("tar stream over the plain-archive bound")

// boundedReader returns errTarPlainBound once more than n bytes were read.
type boundedReader struct {
	r io.Reader
	n int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.n < 0 {
		return 0, errTarPlainBound
	}
	read, err := b.r.Read(p)
	b.n -= int64(read)
	if b.n < 0 {
		return read, errTarPlainBound
	}
	return read, err
}

// tarArchiveHoldsNoLink reports a static tar extraction whose one archive
// file holds only regular files and directories with relative names and no
// .. component, so it makes no link in its destination
// (rel-1-0-6:GAP-0339): tar -xf plain.tar -C d1 && cp -a d1 e3 && echo k
// >> e3/p writes a plain file. The destination must be known (tarScan),
// the archive word must appear once in the command, and the archive must
// be plain, gzip or bzip2. The caller also requires that no statement
// before the extraction can write a file (onlyDirectoryStatementsBefore):
// another name for the archive (a hard link, a symbolic link) could
// rewrite it first (review 8). The hook client reads the archive and
// records TarPlainFactPrefix; a gateway with client evidence needs the
// fact and its own read of the archive. Anything else keeps the opaque
// reading. A process outside the command can still replace the archive
// between the check and the run, as it can any file a disk walk reads.
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
		// A client claim alone does not clear the scope: the gateway reads
		// the archive itself and needs the fact as well. One that cannot
		// read it (ProtectHome) keeps the opaque reading (review 8).
		return facts[key] == "1" && tarArchivePlain(path)
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
		stream = zipped
	case len(magic) == 3 && string(magic) == "BZh":
		stream = bzip2.NewReader(buffered)
	}
	reader := tar.NewReader(&boundedReader{r: stream, n: maxTarPlainBytes})
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

// onlyDirectoryStatementsBefore reports that every top-level statement
// before the one holding call is a static cd or mkdir, which write no file,
// so nothing in the command can rewrite an archive call reads before it
// runs (rel-1-0-6:GAP-0339 review 8). A call that is not in a top-level
// statement is not read.
func onlyDirectoryStatementsBefore(file *syntax.File, call *syntax.CallExpr, home string) bool {
	if file == nil || call == nil {
		return false
	}
	statements, linear := linearShellStatements(file)
	if !linear {
		return false
	}
	for _, stmt := range statements {
		if stmt.Cmd == syntax.Command(call) {
			return true
		}
		if len(stmt.Redirs) != 0 || stmt.Background || stmt.Negated {
			return false
		}
		earlier, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(earlier.Args) == 0 || len(earlier.Assigns) != 0 {
			return false
		}
		program, static := StaticWord(earlier.Args[0], home)
		if !static || program != "cd" && program != "mkdir" {
			return false
		}
		for _, arg := range earlier.Args[1:] {
			if _, fixed := StaticWord(arg, home); !fixed {
				return false
			}
		}
	}
	return false
}
