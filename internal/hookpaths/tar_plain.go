// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"io"
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
// before the extraction can write a file and that the extraction statement
// has no redirection (onlyDirectoryStatementsBefore): another name for the
// archive (a hard link, a symbolic link) could rewrite it before tar opens
// it (reviews 8 and 9). The hook client reads the archive and
// records TarPlainFactPrefix; a gateway with client evidence needs the
// fact and its own read of the archive. Anything else keeps the opaque
// reading. A process outside the command can still replace the archive
// between the check and the run, as it can any file a disk walk reads.
// plain is the reading of the archive (archiveReading): members of plain
// kind that land on none of the protected names.
func tarArchiveHoldsNoLink(program string, args []string, static []bool, cwd, command string, plain func(string) bool, facts map[string]string, record bool) bool {
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
	return archivePlainWithFacts(OperandPath(archive, cwd), plain, facts, record)
}

// archivePlainWithFacts reads the archive at path with plain and keeps the
// hook client's TarPlainFactPrefix evidence for it.
func archivePlainWithFacts(path string, plain func(string) bool, facts map[string]string, record bool) bool {
	key := TarPlainFactPrefix + path
	if !record && facts != nil {
		// A client claim alone does not clear the scope: the gateway reads
		// the archive itself and needs the fact as well. One that cannot
		// read it (ProtectHome) keeps the opaque reading (review 8).
		return facts[key] == "1" && plain(path)
	}
	ok := plain(path)
	if record && facts != nil && ok {
		facts[key] = "1"
	}
	return ok
}

// archiveExtractionHoldsNoLink reports an extraction call that makes no
// link in its destination: a tar or unzip of one archive file whose every
// member is a plain file or folder with a relative name and no ..
// (tarArchivePlain, zipArchivePlain), read where the call opens it.
//
// The archive is read at its own name when nothing before the call can
// write a file (onlyDirectoryStatementsBefore, rel-1-0-6:GAP-0339). It is
// also read when the one statement before it that writes is a plain mv or
// cp of an existing regular file onto the archive name (stagedArchiveSource:
// mv ~/Downloads/app.tar.gz ~/projects/ && tar xzf ~/projects/app.tar.gz -C
// ~/projects): the archive tar opens is that file's content, so that file is
// read (rel-1-0-10:GAP-0593). Before this, a staged archive was never read,
// the extraction folder in the home was an opaque link scope, and the call
// blocked as an SSH key write in every pack.
func archiveExtractionHoldsNoLink(file *syntax.File, call *syntax.CallExpr, program string, args []string, static []bool, cwd, command, home string, facts map[string]string, record bool) bool {
	plain, ok := archiveReading(program, args, static, cwd, home)
	if !ok {
		return false
	}
	if onlyDirectoryStatementsBefore(file, call, home) {
		if tarArchiveHoldsNoLink(program, args, static, cwd, command, plain, facts, record) {
			return true
		}
		if archive, ok := extractionArchive(program, args, static, cwd); ok && program == "unzip" &&
			strings.Count(command, filepath.Base(archive)) == 1 {
			return archivePlainWithFacts(archive, plain, facts, record)
		}
		return false
	}
	archive, ok := extractionArchive(program, args, static, cwd)
	if !ok {
		return false
	}
	source, staging, ok := stagedArchiveSource(file, call, command, home, cwd, archive)
	if !ok {
		return false
	}
	// No other statement names the archive or its source, so nothing else
	// in the command can rewrite either (as tarArchiveHoldsNoLink asks of
	// the archive word).
	callText := command[call.Pos().Offset():call.End().Offset()]
	for _, name := range []string{filepath.Base(archive), filepath.Base(source)} {
		if strings.Count(command, name) != strings.Count(staging, name)+strings.Count(callText, name) {
			return false
		}
	}
	return archivePlainWithFacts(source, plain, facts, record)
}

// archiveReading is the reading of the archive an extraction call opens: a
// tar or zip whose members are all plain files and folders with relative
// names (archiveMembers), and none of whose files lands, below the folder
// the call extracts into, on a protected name (archiveLandsProtected;
// rel-1-0-10:GAP-0717). The members decide what an extraction writes, so a
// proof that no member is a link must also tell where the files go: a plain
// file named .ssh/authorized_keys, .bashrc or .claude/settings.json is no
// link and is a write of that file. ok is false for a call whose extraction
// folder or program the words do not tell.
func archiveReading(program string, args []string, static []bool, cwd, home string) (func(string) bool, bool) {
	folder, wide, ok := extractionFolder(program, args, static, cwd)
	if !ok {
		return nil, false
	}
	read := tarArchiveMembers
	if program == "unzip" {
		read = zipArchiveMembers
	}
	return func(path string) bool {
		members, ok := read(path)
		return ok && !archiveLandsProtected(members, folder, home, wide)
	}, true
}

// extractionFolder is the absolute folder a static tar or unzip call
// extracts into, and whether it can move a member up a level: tar
// --strip-components or unzip -j (wide), so a member lands at any suffix of
// its name. ok is false for any other program and for a word that is not
// static.
func extractionFolder(program string, args []string, static []bool, cwd string) (folder string, wide, ok bool) {
	if !filepath.IsAbs(cwd) {
		return "", false, false
	}
	folder = cwd
	switch {
	case strings.HasSuffix(program, "tar"):
		var scanned bool
		if folder, _, _, scanned = tarScan(args, static, cwd); !scanned {
			return "", false, false
		}
		for _, arg := range args {
			if name, long := strings.CutPrefix(arg, "--"); long {
				name, _, _ = strings.Cut(name, "=")
				wide = wide || name != "" && strings.HasPrefix("strip-components", name)
			}
		}
	case program == "unzip":
		for i := 0; i < len(args); i++ {
			if !staticAt(static, i) {
				return "", false, false
			}
			arg := args[i]
			if len(arg) < 2 || !strings.HasPrefix(arg, "-") {
				continue
			}
			cluster := arg[1:]
			for j := 0; j < len(cluster); j++ {
				switch cluster[j] {
				case 'd', 'P', 'I', 'O':
					value := cluster[j+1:]
					if value == "" {
						if i++; i >= len(args) || !staticAt(static, i) {
							return "", false, false
						}
						value = args[i]
					}
					if cluster[j] == 'd' {
						folder = value
					}
					j = len(cluster)
				case 'j':
					wide = true
				}
			}
		}
	default:
		return "", false, false
	}
	if !filepath.IsAbs(folder) {
		folder = filepath.Join(cwd, folder)
	}
	return filepath.Clean(folder), wide, true
}

// archiveShellStartupNames are the shell startup files of a home folder.
var archiveShellStartupNames = map[string]bool{
	".bashrc": true, ".bash_profile": true, ".bash_login": true, ".bash_aliases": true, ".profile": true,
	".zshenv": true, ".zprofile": true, ".zshrc": true, ".zlogin": true,
}

// archiveLandsProtected reports a member file that lands on a protected
// name below folder: a protected file (authorized keys, the SSH control and
// key files, the DefenseClaw state, as protectedReachPath reads them), a
// shell startup file of the home, a hook settings file or Git hook (a
// boundFolderNames name in a boundAgentFolders folder) or a sudoers file. A
// wide extraction (tar --strip-components, unzip -j) can drop leading
// components, so every suffix of the member name is tried.
func archiveLandsProtected(members []string, folder, home string, wide bool) bool {
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	for _, member := range members {
		parts := strings.Split(member, "/")
		for start := 0; start < len(parts); start++ {
			target := filepath.Join(folder, filepath.Join(parts[start:]...))
			if protectedReachPath(target, protected, ssh) || archiveNamesProtected(target, home) {
				return true
			}
			if !wide {
				break
			}
		}
	}
	return false
}

// archiveNamesProtected reads a landing path by its names.
func archiveNamesProtected(target, home string) bool {
	if archiveShellStartupNames[strings.ToLower(filepath.Base(target))] && filepath.Dir(target) == filepath.Clean(home) {
		return true
	}
	components := strings.Split(strings.ToLower(filepath.ToSlash(target)), "/")
	for i, component := range components {
		if component == "sudoers" || component == "sudoers.d" {
			return true
		}
		if i+1 < len(components) && boundAgentFolders[component] && boundFolderNames[components[i+1]] {
			return true
		}
	}
	return false
}

// extractionArchive is the absolute path of the one archive file a static
// tar extraction (tarScan, tarArchiveWord) or unzip call (unzipArchiveWord)
// reads.
func extractionArchive(program string, args []string, static []bool, cwd string) (string, bool) {
	if !filepath.IsAbs(cwd) {
		return "", false
	}
	var archive string
	switch {
	case strings.HasSuffix(program, "tar"):
		if _, _, extract, ok := tarScan(args, static, cwd); !ok || !extract {
			return "", false
		}
		word, ok := tarArchiveWord(args, static)
		if !ok {
			return "", false
		}
		archive = word
	case program == "unzip":
		word, ok := unzipArchiveWord(args, static)
		if !ok {
			return "", false
		}
		archive = word
	default:
		return "", false
	}
	if archive == "" || archive == "-" || strings.ContainsAny(archive, "*?[$`") {
		return "", false
	}
	return filepath.Clean(OperandPath(archive, cwd)), true
}

// unzipArchiveWord returns the archive operand of a static unzip call: the
// first word that is not an option or the value of -d, -P, -I or -O. A
// pattern or an option this reading does not know keeps it unread.
func unzipArchiveWord(args []string, static []bool) (string, bool) {
	for i := 0; i < len(args); i++ {
		if !staticAt(static, i) {
			return "", false
		}
		arg := args[i]
		if arg == "" || arg == "-" {
			return "", false
		}
		if !strings.HasPrefix(arg, "-") {
			return arg, true
		}
		cluster := arg[1:]
		for j := 0; j < len(cluster); j++ {
			switch cluster[j] {
			case 'd', 'P', 'I', 'O':
				if j+1 == len(cluster) {
					i++
				}
				j = len(cluster)
			case 'q', 'o', 'n', 'j', 'u', 'f', 'a', 'C', 'L', 'D', 'T':
			default:
				return "", false
			}
		}
	}
	return "", false
}

// stagedArchiveSource reports the file a plain mv or cp before call puts at
// archive, and the text of that statement. Every other top-level statement
// before call is a static cd or mkdir (onlyDirectoryStatementsBefore); after
// a cd both operands of the mv or cp must be absolute. The mv or cp has no
// option but -f or -v, no redirection and exactly two static operands; its
// source is an existing regular file (not a link) and its destination is
// archive, or an existing folder where the source keeps its name as archive.
func stagedArchiveSource(file *syntax.File, call *syntax.CallExpr, command, home, cwd, archive string) (source, text string, ok bool) {
	if file == nil || call == nil || !filepath.IsAbs(cwd) {
		return "", "", false
	}
	statements, linear := linearShellStatements(file)
	if !linear {
		return "", "", false
	}
	changed := false
	for _, stmt := range statements {
		if stmt.Cmd == syntax.Command(call) {
			if len(stmt.Redirs) != 0 || source == "" {
				return "", "", false
			}
			return source, text, true
		}
		if len(stmt.Redirs) != 0 || stmt.Background || stmt.Negated {
			return "", "", false
		}
		earlier, isCall := stmt.Cmd.(*syntax.CallExpr)
		if !isCall || len(earlier.Args) == 0 || len(earlier.Assigns) != 0 {
			return "", "", false
		}
		words := make([]string, len(earlier.Args))
		for i, arg := range earlier.Args {
			word, fixed := StaticWord(arg, home)
			if !fixed {
				return "", "", false
			}
			words[i] = word
		}
		switch words[0] {
		case "cd":
			changed = true
			continue
		case "mkdir":
			continue
		case "mv", "cp":
		default:
			return "", "", false
		}
		if source != "" {
			return "", "", false
		}
		var operands []string
		for _, word := range words[1:] {
			switch {
			case word == "-f" || word == "-v":
			case strings.HasPrefix(word, "-"):
				return "", "", false
			default:
				operands = append(operands, word)
			}
		}
		if len(operands) != 2 || changed && (!filepath.IsAbs(operands[0]) || !filepath.IsAbs(operands[1])) {
			return "", "", false
		}
		from := filepath.Clean(OperandPath(operands[0], cwd))
		if info, err := Lstat(from); err != nil || !info.Mode().IsRegular() {
			return "", "", false
		}
		to := filepath.Clean(OperandPath(operands[1], cwd))
		if info, err := pathStat(to); err == nil && info.IsDir() {
			to = filepath.Join(to, filepath.Base(from))
		} else if strings.HasSuffix(operands[1], "/") {
			return "", "", false
		}
		if to != archive {
			return "", "", false
		}
		source, text = from, command[stmt.Pos().Offset():stmt.End().Offset()]
	}
	return "", "", false
}

// zipArchiveMembers reads the zip archive at path and returns its regular
// files, as the slash names they are stored under, when every member is a
// regular file or a folder with a relative name and no .. component, within
// the tar bounds.
func zipArchiveMembers(path string) ([]string, bool) {
	info, err := pathStat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxTarPlainBytes {
		return nil, false
	}
	file, err := pathOpen(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	reader, err := zip.NewReader(file, info.Size())
	if err != nil || len(reader.File) == 0 || len(reader.File) > maxTarPlainMembers {
		return nil, false
	}
	var files []string
	for _, member := range reader.File {
		mode := member.Mode()
		if !mode.IsRegular() && !mode.IsDir() {
			return nil, false
		}
		name := member.Name
		if name == "" || strings.HasPrefix(name, "/") || filepath.IsAbs(name) || strings.Contains(name, "\\") {
			return nil, false
		}
		for _, part := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
			if part == ".." {
				return nil, false
			}
		}
		if mode.IsRegular() {
			files = append(files, strings.TrimSuffix(name, "/"))
		}
	}
	return files, true
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

// tarArchiveMembers reads the archive at path and returns its regular
// files, as the slash names they are stored under, when every member is a
// regular file or a directory with a relative name and no .. component,
// within the bounds.
func tarArchiveMembers(path string) ([]string, bool) {
	info, err := pathStat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxTarPlainBytes {
		return nil, false
	}
	file, err := pathOpen(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	buffered := bufio.NewReader(io.LimitReader(file, maxTarPlainBytes))
	magic, _ := buffered.Peek(3)
	var stream io.Reader = buffered
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		zipped, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, false
		}
		defer zipped.Close()
		stream = zipped
	case len(magic) == 3 && string(magic) == "BZh":
		stream = bzip2.NewReader(buffered)
	}
	reader := tar.NewReader(&boundedReader{r: stream, n: maxTarPlainBytes})
	members := 0
	var files []string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return files, members > 0
		}
		if err != nil {
			return nil, false
		}
		if members++; members > maxTarPlainMembers {
			return nil, false
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		default:
			return nil, false
		}
		name := filepath.ToSlash(header.Name)
		if name == "" || strings.HasPrefix(name, "/") || filepath.IsAbs(header.Name) || strings.Contains(name, "\\") {
			return nil, false
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return nil, false
			}
		}
		if header.Typeflag == tar.TypeReg {
			files = append(files, strings.TrimSuffix(name, "/"))
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
			// A redirection is evaluated before the call and may rewrite the
			// archive through another name, including a hard link.
			return len(stmt.Redirs) == 0
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
