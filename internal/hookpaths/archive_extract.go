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

// ArchiveExtractionPaths returns the absolute paths the archive extractions
// of a shell command write: each folder (ArchiveExtractionDestinations) and
// each member the extraction names, joined below it and normalized
// (ArchiveExtractionMembers), so `tar -xf a.tar -C ~ .defenseclaw/config.yaml`
// is a write of that file (rel-1-0-10:GAP-0142). Each word is expanded as the
// shell would from the home alone (quotes, ~/, $HOME; a word with any other
// expansion is skipped) and a relative folder is placed in cwd. A leading
// sudo, env, nice, nohup, time, command, exec or timeout is looked through. It
// is nil when the command does not parse.
func ArchiveExtractionPaths(command, cwd, home string) []string {
	paths, _ := ArchiveExtractionReading(command, cwd, home)
	return paths
}

// ArchiveExtractionReading is ArchiveExtractionPaths with the caps the
// reading hit. A shell -c body (and su -c, script -c, ssh) is read as a
// command of its own down to InlineMaxShellDepth levels; a body nested deeper,
// or a wrapper chain longer than actionfacts.InlineChainRounds, is TRUNCATED
// (bound rule, cap depth): what it extracts is unknown
// (rel-1-0-10:GAP-0663).
func ArchiveExtractionReading(command, cwd, home string) ([]string, bounded.CapSet) {
	paths, _, caps := ArchiveExtractionUnknown(command, cwd, home)
	return paths, caps
}

// ArchiveExtractionUnknown is ArchiveExtractionReading with the folders of
// the extractions whose members the words do not tell: a member glob, a list
// read from a file (tar -T), a rename of the members (tar --transform, bsdtar
// -s). Whatever such an extraction writes below its folder is unknown
// (rel-1-0-10:GAP-0142).
func ArchiveExtractionUnknown(command, cwd, home string) (paths, unknown []string, caps bounded.CapSet) {
	file, parsed := parseShell(command)
	if !parsed || !filepath.IsAbs(cwd) {
		return nil, nil, bounded.CapSet{}
	}
	var trunc bounded.Truncated
	archiveWalk(file, cwd, home, 0, &paths, &unknown, &trunc)
	return paths, unknown, trunc.Set()
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

func archiveWalk(file *syntax.File, cwd, home string, depth int, out, unknown *[]string, trunc *bounded.Truncated) {
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		for index, arg := range call.Args {
			words[index], _ = StaticWord(arg, home)
		}
		if child, _, caps := actionfacts.InlineChild(words); len(child) > 0 {
			trunc.Merge(caps)
			if body, shell := launcherBody(child); shell {
				if trunc.Within(bounded.Depth, depth+1, InlineMaxShellDepth) {
					if inner, parsed := parseShell(body); parsed {
						archiveWalk(inner, cwd, home, depth+1, out, unknown, trunc)
					}
				}
				return true
			}
		}
		words = archiveProgramWords(words)
		if len(words) == 0 {
			return true
		}
		members := ArchiveExtractionMembers(words[0], words[1:])
		for _, folder := range ArchiveExtractionDestinations(words[0], words[1:]) {
			if folder == "" || strings.HasPrefix(folder, "~") {
				continue
			}
			if !filepath.IsAbs(folder) {
				folder = filepath.Join(cwd, folder)
			}
			*out = append(*out, filepath.Clean(folder))
			if archiveMembersUnknown(words[0], words[1:]) {
				*unknown = append(*unknown, filepath.Clean(folder))
			}
			for _, member := range members {
				*out = append(*out, archiveMemberPath(folder, member))
			}
		}
		return true
	})
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
