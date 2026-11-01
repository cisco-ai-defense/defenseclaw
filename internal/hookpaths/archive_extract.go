// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
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
		case word == "--extract" || word == "--get":
			extract = true
		case word == "--directory":
			next()
		case strings.HasPrefix(word, "--directory="):
			destinations = append(destinations, strings.TrimPrefix(word, "--directory="))
		case strings.HasPrefix(word, "--"):
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

// ArchiveExtractionFolders returns the absolute folders the archive
// extractions of a shell command write in (ArchiveExtractionDestinations),
// with each word expanded as the shell would from the home alone (quotes,
// ~/, $HOME; a word with any other expansion is skipped) and a relative
// folder placed in cwd. A leading sudo, env, nice, nohup, time, command,
// exec or timeout is looked through. It is nil when the command does not
// parse.
func ArchiveExtractionFolders(command, cwd, home string) []string {
	file, parsed := parseShell(command)
	if !parsed || !filepath.IsAbs(cwd) {
		return nil
	}
	var out []string
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		for index, arg := range call.Args {
			words[index], _ = StaticWord(arg, home)
		}
		words = archiveProgramWords(words)
		if len(words) == 0 {
			return true
		}
		for _, folder := range ArchiveExtractionDestinations(words[0], words[1:]) {
			if folder == "" || strings.HasPrefix(folder, "~") {
				continue
			}
			if !filepath.IsAbs(folder) {
				folder = filepath.Join(cwd, folder)
			}
			out = append(out, filepath.Clean(folder))
		}
		return true
	})
	return out
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
