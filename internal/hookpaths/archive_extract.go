// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// ArchiveExtractionDestinations returns the folders an archive extraction
// writes in, as spelled (relative words are relative to the command's
// directory; "." is that directory), given the static words after the
// program ("" for a word with no static spelling). It is nil for a call
// that does not extract (a listing, a test, a create, or output to
// stdout). unzip -d, tar -C/--directory, 7z -o, cpio -D and the ditto
// destination are covered (GAP-2415).
func ArchiveExtractionDestinations(program string, words []string) []string {
	switch strings.ToLower(filepath.Base(program)) {
	case "unzip":
		return unzipDestinations(words)
	case "tar", "gtar", "bsdtar":
		return tarDestinations(words)
	case "7z", "7za", "7zr":
		if len(words) == 0 || words[0] != "x" && words[0] != "e" {
			return nil
		}
		destination := "."
		for _, word := range words[1:] {
			if strings.HasPrefix(word, "-o") && len(word) > 2 {
				destination = word[2:]
			}
		}
		return []string{destination}
	case "cpio", "bsdcpio":
		return cpioDestinations(words)
	case "ditto":
		var operands []string
		for index := 0; index < len(words); index++ {
			word := words[index]
			switch {
			case word == "--arch" || word == "--bom":
				index++
			case strings.HasPrefix(word, "-") && len(word) > 1:
			default:
				operands = append(operands, word)
			}
		}
		if len(operands) < 2 {
			return nil
		}
		return []string{operands[len(operands)-1]}
	}
	return nil
}

func unzipDestinations(words []string) []string {
	destination := "."
	for index := 0; index < len(words); index++ {
		word := words[index]
		if !strings.HasPrefix(word, "-") || len(word) < 2 {
			continue
		}
		if word == "-x" {
			// Names to exclude follow, up to the next option.
			continue
		}
		cluster := word[1:]
		if position := strings.IndexByte(cluster, 'd'); position >= 0 {
			if strings.ContainsAny(cluster[:position], "lptvzZc") {
				return nil
			}
			if value := cluster[position+1:]; value != "" {
				destination = value
			} else if index+1 < len(words) {
				destination = words[index+1]
				index++
			}
			continue
		}
		// List, pipe, test, verbose, comment, zipinfo and stdout modes
		// write no file.
		if strings.ContainsAny(cluster, "lptvzZc") {
			return nil
		}
	}
	return []string{destination}
}

func tarDestinations(words []string) []string {
	extract := false
	var destinations []string
	for index, word := range words {
		next := func() {
			if index+1 < len(words) {
				destinations = append(destinations, words[index+1])
			}
		}
		switch {
		case strings.HasPrefix(word, "--") && len(word) > 2:
			name, value, attached := strings.Cut(word, "=")
			switch tarLongName(name) {
			case "--extract", "--get":
				extract = true
			case "--directory":
				if attached {
					destinations = append(destinations, value)
				} else {
					next()
				}
			}
		case strings.HasPrefix(word, "-") && len(word) > 1:
			cluster := word[1:]
			if strings.ContainsRune(cluster, 'x') {
				extract = true
			}
			if position := strings.IndexByte(cluster, 'C'); position >= 0 {
				if value := cluster[position+1:]; value != "" && !strings.ContainsAny(cluster[:position], "f") {
					destinations = append(destinations, value)
				} else {
					next()
				}
			}
		case index == 0:
			// Old-style bundled letters: tar xf a.tar.
			if strings.ContainsRune(word, 'x') {
				extract = true
			}
		}
	}
	if !extract {
		return nil
	}
	if len(destinations) == 0 {
		return []string{"."}
	}
	return destinations
}

func cpioDestinations(words []string) []string {
	mode := byte(0)
	destination := "."
	var operands []string
	for index := 0; index < len(words); index++ {
		word := words[index]
		switch {
		case word == "--extract":
			mode = 'i'
		case word == "--pass-through":
			mode = 'p'
		case word == "-D" || word == "--directory":
			if index+1 < len(words) {
				destination = words[index+1]
				index++
			}
		case strings.HasPrefix(word, "--directory="):
			destination = strings.TrimPrefix(word, "--directory=")
		case strings.HasPrefix(word, "--"):
		case strings.HasPrefix(word, "-") && len(word) > 1:
			for _, letter := range []byte{'i', 'p', 'o'} {
				if strings.IndexByte(word[1:], letter) >= 0 {
					mode = letter
				}
			}
		default:
			operands = append(operands, word)
		}
	}
	switch mode {
	case 'i':
		return []string{destination}
	case 'p':
		if len(operands) > 0 {
			return []string{operands[0]}
		}
	}
	return nil
}

// ArchiveExtractions is what the archive extractions of one command write
// (ReadArchiveExtractions).
type ArchiveExtractions struct {
	// Paths are the folders the extractions write in and the members their
	// words name, absolute and clean.
	Paths []string
	// Unknown are the folders of the extractions whose members the words do
	// not tell: a member glob, a list read from a file (tar -T), a rename of
	// the members (tar --transform, bsdtar -s). Whatever such an extraction
	// writes below its folder is unknown (rel-1-0-10:GAP-0142).
	Unknown []string
	// Whole are the extractions of every member of one archive file a word
	// names (ArchiveWhole).
	Whole []ArchiveWhole
	// Caps are the bounds the reading hit.
	Caps bounded.CapSet
}

// ArchiveWhole is an extraction of every member of one archive file into
// Folder: a tar or unzip call that names no member, Expand-Archive, the .NET
// ZipFile ExtractToDirectory call, Python tarfile and zipfile extractall and
// shutil.unpack_archive (rel-1-0-10:GAP-1173). Its words do not tell where
// the members land; the archive does (Landing).
type ArchiveWhole struct {
	Folder, Archive string
	format          archiveFormat
	// renamed: the call changes the member names (tar --strip-components,
	// unzip -j), so the listing does not tell where they land.
	renamed bool
	// staged: the command names the archive before the extraction (a cp or
	// mv onto it, a download to it) after a statement that may write a
	// file, so the archive the extraction opens is not the file there at
	// hook time (rel-1-0-10:GAP-1224, as the plain-archive reader asks:
	// rel-1-0-6:GAP-0339, rel-1-0-10:GAP-0593).
	staged bool
}

type archiveFormat uint8

const (
	archiveTar archiveFormat = iota + 1
	archiveZip
	// archiveAny is read as a zip and else as a tar (shutil.unpack_archive
	// of a name it guesses the format of).
	archiveAny
)

// Landing lists where the members of the archive land below the folder.
// present reports that the archive file is there to be read: a missing one
// (made by an earlier statement, or out of the reach of a managed gateway)
// and one on a network share that has not answered are not. listed reports
// that every member was read, within the bounds of the plain-archive reading
// (64 MiB, 4096 members), as a regular file or folder with a relative name
// and no .. component, and that the call keeps the member names.
func (whole ArchiveWhole) Landing() (paths []string, present, listed bool) {
	info, err := pathStat(whole.Archive)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false, false
	}
	if whole.renamed || whole.staged {
		return nil, true, false
	}
	var members []string
	switch whole.format {
	case archiveTar:
		members, listed = tarArchiveMembers(whole.Archive)
	case archiveZip:
		members, listed = zipArchiveMembers(whole.Archive)
	case archiveAny:
		if members, listed = zipArchiveMembers(whole.Archive); !listed {
			members, listed = tarArchiveMembers(whole.Archive)
		}
	}
	if !listed {
		return nil, true, false
	}
	for _, member := range members {
		paths = append(paths, archiveMemberPath(whole.Folder, member))
	}
	return paths, true, true
}

// ReadArchiveExtractions reads the archive extractions of a command: the
// shell calls (tar, unzip, 7z, cpio, ditto, and python -c code that calls
// tarfile, zipfile or shutil.unpack_archive) and, on a command that names
// one, the PowerShell Expand-Archive and ZipFile ExtractToDirectory calls
// (rel-1-0-10:GAP-1173). Paths are the absolute paths they write: each folder
// (ArchiveExtractionDestinations) and each member the extraction names,
// joined below it and normalized (ArchiveExtractionMembers), so
// `tar -xf a.tar -C ~ .defenseclaw/config.yaml` is a write of that file
// (rel-1-0-10:GAP-0142). Each shell word is expanded as the shell would from
// the home alone (quotes, ~/, $HOME; a word with any other expansion is
// skipped) and a relative folder is placed in cwd. A leading sudo, env, nice,
// nohup, time, command, exec or timeout is looked through. A shell -c body
// (and su -c, script -c, ssh) is read as a command of its own down to
// InlineMaxShellDepth levels; a body nested deeper, or a wrapper chain longer
// than actionfacts.InlineChainRounds, is TRUNCATED (bound rule, cap depth) in
// Caps: what it extracts is unknown (rel-1-0-10:GAP-0663). windowsShell says
// the command runs in a native Windows shell (a Windows hook host): its tar,
// unzip and 7z calls are then also read with PowerShell words, so a
// backslash folder (tar -xf x.tar -C C:\Users\u\.defenseclaw, or
// $env:USERPROFILE\.defenseclaw, ~\.defenseclaw) is the folder PowerShell
// hands the program, where the POSIX reading of the same text drops the
// backslashes and the $env: word (rel-1-0-10:GAP-1633).
func ReadArchiveExtractions(command, cwd, home string, windowsShell bool) ArchiveExtractions {
	var read archiveExtractionScan
	if file, parsed := parseShell(command); parsed && filepath.IsAbs(cwd) {
		archiveWalk(file, command, cwd, home, 0, &read)
	}
	powerShellArchiveExtractions(command, cwd, home, windowsShell, &read)
	return ArchiveExtractions{Paths: read.paths, Unknown: read.unknown, Whole: read.whole, Caps: read.trunc.Set()}
}

// archiveExtractionScan collects one ReadArchiveExtractions.
type archiveExtractionScan struct {
	paths, unknown []string
	whole          []ArchiveWhole
	listings       []archiveListingSpan
	trunc          bounded.Truncated
}

// archiveListingSpan is the byte range of a tar listing call (tar -tf x.tar,
// actionTarListsOnly) in the text it was read from.
type archiveListingSpan struct {
	text       string
	start, end int
}

// archiveListing reports a tar call that only lists an archive: every word
// static and actionTarListsOnly. It reads the archive and writes no file.
func archiveListing(words []string, static []bool) bool {
	switch strings.ToLower(strings.TrimSuffix(filepath.Base(words[0]), ".exe")) {
	case "tar", "gtar", "bsdtar":
	default:
		return false
	}
	for _, known := range static {
		if !known {
			return false
		}
	}
	return actionTarListsOnly(words[1:])
}

// textBefore is text up to at with the tar listings read from it that end
// there blanked: a mention of an archive in a listing of it is a read, not a
// write that may stage it (rel-1-0-10:GAP-1662).
func (read *archiveExtractionScan) textBefore(text string, at int) string {
	before := text[:at]
	var blanked []byte
	for _, listing := range read.listings {
		if listing.start < 0 || listing.start >= listing.end || listing.end > at || listing.text != text {
			continue
		}
		if blanked == nil {
			blanked = []byte(before)
		}
		for index := listing.start; index < listing.end; index++ {
			blanked[index] = ' '
		}
	}
	if blanked == nil {
		return before
	}
	return string(blanked)
}

// archiveMembersUnknown reports an extraction whose members cannot be read
// from its words.
func archiveMembersUnknown(program string, words []string) bool {
	switch strings.ToLower(filepath.Base(program)) {
	case "tar", "gtar", "bsdtar":
		for _, word := range words {
			if strings.HasPrefix(word, "--") {
				switch tarLongName(strings.SplitN(word, "=", 2)[0]) {
				case tminTable(tminTarMemberList)[0], tminTable(tminTarMemberList)[1], tminTable(tminTarMemberList)[2]:
					return true
				}
				continue
			}
			if strings.HasPrefix(word, "-") && len(word) > 1 && (strings.Contains(word[1:], "T") && !strings.Contains(word[1:], "f") ||
				word == "-T" || strings.HasPrefix(word, "-s") && strings.Contains(filepath.Base(program), "bsdtar")) {
				return true
			}
		}
	}
	for _, member := range ArchiveExtractionMembers(program, words) {
		if strings.ContainsAny(member, "*?[") {
			return true
		}
	}
	return false
}

func archiveWalk(file *syntax.File, text, cwd, home string, depth int, read *archiveExtractionScan) {
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		// Whole archives this call extracts are staged when the command may
		// write them first (archiveStagedBefore).
		first := len(read.whole)
		defer func() {
			for index := first; index < len(read.whole); index++ {
				if archiveStagedBefore(file, call, text, home, read.whole[index].Archive, read) {
					read.whole[index].staged = true
				}
			}
		}()
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for index, arg := range call.Args {
			words[index], static[index] = StaticWord(arg, home)
		}
		if child, _, caps := actionfacts.InlineChild(words); len(child) > 0 {
			read.trunc.Merge(caps)
			if body, shell := launcherBody(child); shell {
				if read.trunc.Within(bounded.Depth, depth+1, InlineMaxShellDepth) {
					if inner, parsed := parseShell(body); parsed {
						archiveWalk(inner, body, cwd, home, depth+1, read)
					}
				}
				return true
			}
		}
		words = archiveProgramWords(words)
		if len(words) == 0 {
			return true
		}
		static = static[len(static)-len(words):]
		program := strings.ToLower(filepath.Base(words[0]))
		if program == "python" || strings.HasPrefix(program, "python3") {
			if code, ok := pythonLiteralCode(words); ok {
				pythonArchiveExtractions(code, cwd, home, read)
			}
			return true
		}
		if archiveListing(words, static) {
			read.listings = append(read.listings, archiveListingSpan{text: text, start: int(call.Pos().Offset()), end: int(call.End().Offset())})
			return true
		}
		archiveCallExtractions(words, static, cwd, read)
		return true
	})
}

// archiveCallExtractions reads one extractor call: words are the program and
// the words it is handed ("" where static is false: a word with no static
// spelling), a relative folder is placed in cwd. The shell reading
// (archiveWalk) and the PowerShell reading of a native call
// (psNativeArchiveCall) share it.
func archiveCallExtractions(words []string, static []bool, cwd string, read *archiveExtractionScan) {
	program := strings.ToLower(filepath.Base(words[0]))
	members := ArchiveExtractionMembers(words[0], words[1:])
	unknown := archiveMembersUnknown(words[0], words[1:])
	// A call that names no member extracts the whole archive: where its
	// members land is read from the archive (rel-1-0-10:GAP-1173).
	var whole ArchiveWhole
	if len(members) == 0 && !unknown {
		if archive, ok := extractionArchive(program, words[1:], static[1:], cwd); ok {
			whole = ArchiveWhole{Archive: archive, format: archiveTar, renamed: archiveRenamesMembers(program, words[1:])}
			if program == "unzip" {
				whole.format = archiveZip
			}
		}
	}
	for _, folder := range ArchiveExtractionDestinations(words[0], words[1:]) {
		if folder == "" || strings.HasPrefix(folder, "~") {
			continue
		}
		if !filepath.IsAbs(folder) {
			folder = filepath.Join(cwd, folder)
		}
		// The command's own cwd link names a folder below the one it runs
		// in, not the lexical /proc/self/... (rel-1-0-10:GAP-2265).
		if placed, ok := actionfacts.ProcessCWDLinkSpelling(folder, cwd); ok {
			folder = placed
		}
		folder = filepath.Clean(folder)
		read.paths = append(read.paths, folder)
		if unknown {
			read.unknown = append(read.unknown, folder)
		}
		for _, member := range members {
			read.paths = append(read.paths, archiveMemberPath(folder, member))
		}
		if whole.Archive != "" {
			whole.Folder = folder
			read.whole = append(read.whole, whole)
		}
	}
}

// archiveStagedBefore reports that a statement before the extraction call
// may write the archive: the statements before it are not only static cd
// and mkdir (onlyDirectoryStatementsBefore), and the text before the call
// names the archive (rel-1-0-10:GAP-1224) outside a tar listing of it
// (textBefore, rel-1-0-10:GAP-1662). A call the text cannot place is read as
// staged.
func archiveStagedBefore(file *syntax.File, call *syntax.CallExpr, text, home, archive string, read *archiveExtractionScan) bool {
	if archive == "" || onlyDirectoryStatementsBefore(file, call, home) {
		return false
	}
	at := int(call.Pos().Offset())
	if at < 0 || at > len(text) {
		return true
	}
	return strings.Contains(read.textBefore(text, at), filepath.Base(archive))
}

// archiveRenamesMembers reports a tar or unzip extraction that changes the
// names its members land at: tar --strip-components and unzip -j.
func archiveRenamesMembers(program string, words []string) bool {
	for _, word := range words {
		switch {
		case strings.HasPrefix(word, "--"):
			name, _, _ := strings.Cut(word, "=")
			if program != "unzip" && tarLongName(name) == tminTable(tminTarStrip)[0] {
				return true
			}
		case program == "unzip" && strings.HasPrefix(word, "-") && len(word) > 1:
			// The letters up to a d are options; what follows it is its value.
			cluster := word[1:]
			if at := strings.IndexByte(cluster, 'd'); at >= 0 {
				cluster = cluster[:at]
			}
			if strings.IndexByte(cluster, 'j') >= 0 {
				return true
			}
		}
	}
	return false
}

// archiveProgramWords drops the launchers before the program word.
func archiveProgramWords(words []string) []string {
	for len(words) > 0 {
		switch filepath.Base(words[0]) {
		case "sudo", "nice", "nohup", "time", "command", "exec":
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				words = words[1:]
			}
		case "busybox", "toybox":
			words = words[1:]
		case "env":
			words = words[1:]
			for len(words) > 0 && (strings.HasPrefix(words[0], "-") || strings.Contains(words[0], "=")) {
				words = words[1:]
			}
		case "timeout":
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				words = words[1:]
			}
			if len(words) > 0 {
				words = words[1:]
			}
		default:
			return words
		}
	}
	return words
}

// archiveMemberPath is where a member lands: below the folder, or at its own
// absolute name when tar keeps it (-P).
func archiveMemberPath(folder, member string) string {
	if archiveAbsolute(member) {
		return filepath.Clean(member)
	}
	return filepath.Join(folder, filepath.FromSlash(member))
}

// archiveAbsolute reports an absolute member name, spelled with a slash or as
// a drive path.
func archiveAbsolute(name string) bool {
	return strings.HasPrefix(name, "/") || filepath.IsAbs(name)
}

// ArchiveExtractionMembers lists the members a tar or unzip extraction names
// after its archive, each as the relative name it lands at below the
// destination: a leading / is dropped, tar --strip-components is applied and
// unzip -j keeps only the base name. A member extracted to stdout (tar -O)
// or only listed (tar -t, unzip -l -p -t -Z) writes nothing and is not
// listed; neither is a member an exclusion names. tar -P keeps an absolute
// member as it is (it lands there, whatever the destination). An extraction
// that names no member lists none: it extracts the whole archive.
func ArchiveExtractionMembers(program string, words []string) []string {
	switch strings.ToLower(filepath.Base(program)) {
	case "unzip":
		return unzipMembers(words)
	case "tar", "gtar", "bsdtar":
		return tarMembers(words)
	case "7z", "7za", "7zr":
		return sevenZipMembers(words)
	}
	return nil
}

// sevenZipMembers lists the members 7z x names after its archive.
func sevenZipMembers(words []string) []string {
	if len(words) < 2 || words[0] != "x" && words[0] != "e" {
		return nil
	}
	var operands []string
	for _, word := range words[1:] {
		if !strings.HasPrefix(word, "-") {
			operands = append(operands, word)
		}
	}
	var members []string
	for _, operand := range operands[min(1, len(operands)):] {
		members = append(members, path.Clean(strings.TrimLeft(filepath.ToSlash(operand), "/")))
	}
	return members
}

// tarValueLetters are the tar short options whose value is the rest of the
// cluster or the next word; tarValueOptions the long ones whose value is
// the next word when it is not attached (both from tminTableSpec).
var (
	tarValueLetters = tminTable(tminTarValueLetters)[0]
	tarValueOptions = tminTableSet(tminTarValueOptions)
)

func tarMembers(words []string) []string {
	var operands []string
	extract, stdout, absolute, strip := false, false, false, 0
	for i := 0; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "--":
			operands = append(operands, words[i+1:]...)
			i = len(words)
		case strings.HasPrefix(word, "--"):
			name, value, attached := strings.Cut(word, "=")
			name = tarLongName(name)
			switch name {
			case "--extract", "--get":
				extract = true
			case tminTable(tminTarStdout)[0], tminTable(tminTarStdout)[1], tminTable(tminTarStdout)[2]:
				stdout = true
			case "--absolute-names":
				absolute = true
			}
			if !attached && tarValueOptions[name] {
				if i++; i < len(words) {
					value = words[i]
				}
			}
			if name == tminTable(tminTarStrip)[0] {
				strip, _ = strconv.Atoi(value)
			}
		case strings.HasPrefix(word, "-") && len(word) > 1 || i == 0:
			cluster, dashed := strings.TrimPrefix(word, "-"), strings.HasPrefix(word, "-")
			values := 0
			for at := 0; at < len(cluster); at++ {
				switch cluster[at] {
				case 'x':
					extract = true
				case 'O', 't':
					stdout = true
				case 'P':
					absolute = true
				}
				if strings.IndexByte(tarValueLetters, cluster[at]) < 0 {
					continue
				}
				if dashed {
					// The rest of the cluster is the value; at its end the
					// next word is.
					if at+1 == len(cluster) {
						values++
					}
					break
				}
				values++
			}
			i += values
		default:
			operands = append(operands, word)
		}
	}
	if !extract || stdout {
		return nil
	}
	var members []string
	for _, operand := range operands {
		if absolute && archiveAbsolute(operand) {
			members = append(members, operand)
		}
		parts := strings.Split(path.Clean(strings.TrimLeft(filepath.ToSlash(operand), "/")), "/")
		if strip > 0 {
			if len(parts) <= strip {
				continue
			}
			parts = parts[strip:]
		}
		members = append(members, strings.Join(parts, "/"))
	}
	return members
}

func unzipMembers(words []string) []string {
	archive, excluding, junk := "", false, false
	var named []string
	for i := 0; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "-x":
			excluding = true
		case strings.HasPrefix(word, "-") && len(word) > 1:
			// The letters up to a d are options; what follows it is its value.
			cluster, last := word[1:], false
			if at := strings.IndexByte(cluster, 'd'); at >= 0 {
				cluster, last = cluster[:at+1], at+2 == len(word)
			}
			if strings.ContainsAny(cluster, "lptvzZc") {
				return nil
			}
			junk = junk || strings.IndexByte(cluster, 'j') >= 0
			if last || word == "-P" {
				i++
			}
		case archive == "":
			archive = word
		case !excluding:
			named = append(named, word)
		}
	}
	var members []string
	for _, name := range named {
		name = path.Clean(strings.TrimLeft(filepath.ToSlash(name), "/"))
		if junk {
			name = path.Base(name)
		}
		members = append(members, name)
	}
	return members
}

// tarLongName is the long option a --word spells: exactly, else as the only
// option it is a prefix of (getopt_long: --ext is --extract, --dir is
// --directory); the word itself for one the shared table does not list.
func tarLongName(word string) string {
	switch option := ExpandLongOption(strings.TrimPrefix(word, "--"), tarLongOptions); option {
	case "":
		return word
	case "dir", "cd":
		return "--directory"
	default:
		return "--" + option
	}
}
