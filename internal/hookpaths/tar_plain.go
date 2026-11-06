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
	maxTarPlainBytes    = 64 << 20
	maxTarPlainMembers  = 4096
	maxTarEvidenceWords = 2
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

// tarArchiveLinkEvidence records or reads positive scope-retaining tar evidence.
// A readable non-plain archive retains its scope even in a compound command.
func tarArchiveLinkEvidence(program string, args []string, static []bool, cwd string, facts map[string]string, record bool) bool {
	if !strings.HasSuffix(program, "tar") || !filepath.IsAbs(cwd) {
		return false
	}
	if _, _, extract, ok := tarScan(args, static, cwd); !ok || !extract {
		return false
	}
	archives := tarArchiveWords(args, static)
	if len(archives) > maxTarEvidenceWords {
		// The operand list exceeded the bounded archive read. Keep its
		// scope rather than treating a skipped archive as plain.
		return true
	}
	for _, archive := range archives {
		if archive == "" || archive == "-" || strings.ContainsAny(archive, "*?[$`") {
			continue
		}
		path := OperandPath(archive, cwd)
		if !record && facts != nil && facts[TarLinkFactPrefix+path] == "1" {
			return true
		}
		if tarArchiveKind(path) == 2 {
			if record && facts != nil {
				facts[TarLinkFactPrefix+path] = "1"
			}
			return true
		}
	}
	return false
}

// tarArchivePriorLinkedRewrite finds a known link-bearing archive copied or
// moved onto the archive this extraction will read. The destination may be a
// hard-linked name of that archive. Redirection substitutions on the tar
// statement run before tar opens its archive, so their calls count too.
func tarArchivePriorLinkedRewrite(file *syntax.File, extraction *syntax.CallExpr, args []string, static []bool, cwd, home string, facts map[string]string, record bool) bool {
	archive, ok := tarArchiveWord(args, static)
	if !ok || archive == "" || archive == "-" || file == nil || extraction == nil {
		return false
	}
	archivePath := OperandPath(archive, cwd)
	if !record && facts != nil && facts[TarLinkFactPrefix+archivePath] == "1" {
		return true
	}
	archiveInfo, _ := os.Stat(archivePath)
	matchesArchive := func(destination string) bool {
		path := OperandPath(destination, cwd)
		if path == archivePath {
			return true
		}
		info, err := os.Stat(path)
		return err == nil && archiveInfo != nil && os.SameFile(info, archiveInfo)
	}
	var redirectRanges [][2]syntax.Pos
	statements := make(map[*syntax.CallExpr]*syntax.Stmt)
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			statements[call] = stmt
		}
		if stmt.Cmd != syntax.Command(extraction) {
			return true
		}
		for _, redirect := range stmt.Redirs {
			redirectRanges = append(redirectRanges, [2]syntax.Pos{redirect.Pos(), redirect.End()})
		}
		return true
	})
	priorRange := func(start, end syntax.Pos) bool {
		if start.Offset() < extraction.Pos().Offset() {
			return true
		}
		for _, span := range redirectRanges {
			if span[0].Offset() <= start.Offset() && end.Offset() <= span[1].Offset() {
				return true
			}
		}
		return false
	}
	prior := func(candidate *syntax.CallExpr) bool {
		return priorRange(candidate.Pos(), candidate.End())
	}
	linkedRewrite := false
	linkedPipeline := func(pipe *syntax.BinaryCmd) bool {
		var calls []*syntax.CallExpr
		var collect func(*syntax.Stmt) bool
		collect = func(stmt *syntax.Stmt) bool {
			if nested, ok := stmt.Cmd.(*syntax.BinaryCmd); ok &&
				(nested.Op == syntax.Pipe || nested.Op == syntax.PipeAll) {
				return collect(nested.X) && collect(nested.Y)
			}
			call, ok := stmt.Cmd.(*syntax.CallExpr)
			if ok {
				calls = append(calls, call)
			}
			return ok
		}
		if !collect(pipe.X) || !collect(pipe.Y) {
			return false
		}
		linkedOutput := false
		for _, call := range calls {
			stream := tarArchiveStreamOperands(statements[call], call, home)
			if !stream.ok {
				return false
			}
			linked := stream.readsPipe && linkedOutput
			for _, source := range stream.sources {
				linked = linked || tarArchiveKind(OperandPath(source, cwd)) == 2
			}
			if linked {
				for _, destination := range stream.destinations {
					if matchesArchive(destination) {
						return true
					}
				}
			}
			linkedOutput = linked && stream.passesPipe
		}
		return false
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if pipe, ok := node.(*syntax.BinaryCmd); ok &&
			(pipe.Op == syntax.Pipe || pipe.Op == syntax.PipeAll) &&
			priorRange(pipe.Pos(), pipe.End()) && linkedPipeline(pipe) {
			linkedRewrite = true
			return false
		}
		candidate, ok := node.(*syntax.CallExpr)
		if !ok || candidate == extraction || !prior(candidate) || len(candidate.Args) == 0 {
			return true
		}
		program, fixed := StaticWord(candidate.Args[0], home)
		program = programBase(program)
		if stream := tarArchiveStreamOperands(statements[candidate], candidate, home); fixed && stream.ok {
			for _, source := range stream.sources {
				if tarArchiveKind(OperandPath(source, cwd)) != 2 {
					continue
				}
				for _, destination := range stream.destinations {
					if matchesArchive(destination) {
						linkedRewrite = true
						return false
					}
				}
			}
			return true
		}
		if len(candidate.Args) < 3 {
			return true
		}
		if !fixed || program != "cp" && program != "gcp" &&
			program != "mv" && program != "gmv" && program != "install" {
			return true
		}
		words := make([]string, 0, len(candidate.Args)-1)
		for _, word := range candidate.Args[1:] {
			value, static := StaticWord(word, home)
			if !static {
				return true
			}
			words = append(words, value)
		}
		sources, destination, directoryTarget := []string(nil), "", false
		if programBase(program) == "cp" || programBase(program) == "gcp" {
			parsed := cpOperands(words, makeStatic(len(words)))
			if !parsed.ok {
				return true
			}
			sources, destination, directoryTarget = parsed.sources, parsed.destination, parsed.targetDir || len(parsed.sources) > 1
		} else {
			sources, destination = []string{words[len(words)-2]}, words[len(words)-1]
		}
		for _, source := range sources {
			if strings.HasPrefix(source, "-") || strings.HasPrefix(destination, "-") {
				continue
			}
			sourcePath := OperandPath(source, cwd)
			if tarArchiveKind(sourcePath) != 2 {
				continue
			}
			destinationPath := OperandPath(destination, cwd)
			if info, err := os.Stat(destinationPath); err == nil && info.IsDir() {
				directoryTarget = true
			}
			if directoryTarget {
				destinationPath = filepath.Join(destinationPath, filepath.Base(sourcePath))
			}
			if destinationPath == archivePath {
				linkedRewrite = true
				return false
			}
			if info, err := os.Stat(destinationPath); err == nil && archiveInfo != nil && os.SameFile(info, archiveInfo) {
				linkedRewrite = true
				return false
			}
		}
		return true
	})
	if linkedRewrite && record && facts != nil {
		facts[TarLinkFactPrefix+archivePath] = "1"
	}
	return linkedRewrite
}

// archiveStream describes the bytes a static stream writer reads and writes.
// A stage that reads its own file does not inherit the preceding pipe's bytes.
type archiveStream struct {
	sources, destinations []string
	readsPipe, passesPipe bool
	ok                    bool
}

func tarArchiveStreamOperands(stmt *syntax.Stmt, call *syntax.CallExpr, home string) archiveStream {
	var stream archiveStream
	if call == nil || len(call.Args) == 0 {
		return stream
	}
	program, fixed := StaticWord(call.Args[0], home)
	program = programBase(program)
	if !fixed || program != "cat" && program != "tee" && program != "dd" {
		return stream
	}
	stream.ok, stream.passesPipe = true, true
	stream.readsPipe = program == "tee" || program == "dd" || program == "cat" && len(call.Args) == 1
	for _, word := range call.Args[1:] {
		value, static := StaticWord(word, home)
		if !static {
			return archiveStream{}
		}
		switch program {
		case "cat":
			if value == "-" {
				stream.readsPipe = true
			} else if !strings.HasPrefix(value, "-") {
				stream.sources = append(stream.sources, value)
			}
		case "tee":
			if !strings.HasPrefix(value, "-") {
				stream.destinations = append(stream.destinations, value)
			}
		case "dd":
			if strings.HasPrefix(value, "if=") {
				stream.sources = []string{strings.TrimPrefix(value, "if=")}
				stream.readsPipe = false
			} else if strings.HasPrefix(value, "of=") {
				stream.destinations = []string{strings.TrimPrefix(value, "of=")}
				stream.passesPipe = false
			}
		}
	}
	if program == "cat" && len(stream.sources) == 0 {
		stream.readsPipe = true
	}
	if stmt != nil {
		input, output := "", ""
		readsInput, writesOutput := stream.readsPipe, stream.passesPipe
		redirectedInput := false
		for _, redirect := range stmt.Redirs {
			if redirect.Word == nil {
				continue
			}
			value, static := StaticWord(redirect.Word, home)
			if readsInput && (redirect.Op == syntax.RdrIn || redirect.Op == syntax.RdrInOut) {
				redirectedInput = true
				input = ""
				if static {
					input = value
				}
			}
			switch redirect.Op {
			case syntax.RdrOut, syntax.RdrClob, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
				stream.passesPipe = false
				output = ""
				if static && writesOutput {
					output = value
				}
			}
		}
		stream.readsPipe = readsInput && !redirectedInput
		if input != "" {
			stream.sources = append(stream.sources, input)
		}
		if output != "" {
			stream.destinations = append(stream.destinations, output)
		}
	}
	return stream
}

// tarArchiveWords returns the static archive operands of a tar call.
// Positive scope evidence considers every -f word; plain proof needs one.
func tarArchiveWords(args []string, static []bool) []string {
	var archives []string
	take := func(value string) {
		if len(archives) <= maxTarEvidenceWords {
			archives = append(archives, value)
		}
	}
	for i := 0; i < len(args); i++ {
		if !static[i] {
			return nil
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
						return nil
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
						return nil
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
	return archives
}

// tarArchiveWord returns the unique archive operand required by plain proof.
func tarArchiveWord(args []string, static []bool) (string, bool) {
	archives := tarArchiveWords(args, static)
	if len(archives) != 1 {
		return "", false
	}
	return archives[0], true
}

// tarArchivePlain reads the archive at path and reports that every member
// is a regular file or a directory with a relative name and no ..
// component, within the bounds.
func tarArchivePlain(path string) bool {
	return tarArchiveKind(path) == 1
}

// tarArchiveKind is unknown (0), plain (1), or positive reason to retain the
// conservative scope (2): a non-plain member, unsafe name, or exceeded bound.
func tarArchiveKind(path string) int {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return 0
	}
	if info.Size() > maxTarPlainBytes {
		return 2
	}
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	buffered := bufio.NewReader(io.LimitReader(file, maxTarPlainBytes))
	magic, _ := buffered.Peek(3)
	var stream io.Reader = buffered
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		zipped, err := gzip.NewReader(buffered)
		if err != nil {
			return 0
		}
		defer zipped.Close()
		stream = zipped
	case len(magic) == 3 && string(magic) == "BZh":
		stream = bzip2.NewReader(buffered)
	}
	reader := tar.NewReader(&boundedReader{r: stream, n: maxTarPlainBytes})
	members := 0
	nonPlain := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			if members == 0 {
				return 0
			}
			if nonPlain {
				return 2
			}
			return 1
		}
		if err != nil {
			if errors.Is(err, errTarPlainBound) {
				return 2
			}
			if nonPlain {
				return 2
			}
			return 0
		}
		if members++; members > maxTarPlainMembers {
			return 2
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		default:
			nonPlain = true
		}
		name := filepath.ToSlash(header.Name)
		if name == "" || strings.HasPrefix(name, "/") || filepath.IsAbs(header.Name) || strings.Contains(name, "\\") {
			return 2
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return 2
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
