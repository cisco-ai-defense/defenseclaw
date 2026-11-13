// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// archiveExtractsIntoState reports an archive extraction (unzip -d, tar -C,
// 7z -o, cpio -D, ditto) whose folder is the active state root or a folder
// in it, spelled there or reached through a link: `yes | unzip -q -d
// ~/proj/evil x.zip` with ~/proj/evil -> ~/.defenseclaw replaces
// config.yaml and hooks/ as a redirect through the same link would
// (GAP-2415). ActionFacts gives an extraction no path fact, so it is
// proved from the shell words (hookpaths.ArchiveExtractionFolders); the folder is followed through links with
// the hook's target map first (a managed gateway cannot read the home),
// then the local filesystem when the hook allows it. An extraction into
// the home or a project folder stays allowed.
func archiveExtractsIntoState(facts actionfacts.Facts, request trustedActionRequest) bool {
	home := strings.TrimRight(facts.ActiveHome, "/")
	if !strings.HasPrefix(home, "/") {
		return false
	}
	resolve := stateLinkResolver(request)
	_, inState := stateRootOf(home, resolve)
	spelledRoot := home + "/.defenseclaw"
	fold := runtime.GOOS == "darwin" || runtime.GOOS == "windows"
	spelledInState := func(value string) bool {
		if fold {
			value, spelledRoot := strings.ToLower(value), strings.ToLower(spelledRoot)
			return value == spelledRoot || strings.HasPrefix(value, spelledRoot+"/")
		}
		return value == spelledRoot || strings.HasPrefix(value, spelledRoot+"/")
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return false
	}
	reaches := func(full string) bool {
		if spelledInState(full) {
			return true
		}
		physical, ok := resolve(full)
		if !ok {
			physical, ok = request.ResolvedWriteTargets[hookpaths.DirectoryFactPrefix+full]
		}
		return ok && path.IsAbs(physical) && inState(physical)
	}
	// A member the extraction names lands below its folder by that name:
	// `tar -xf x.tar -C ~ .defenseclaw/config.yaml` writes the state file
	// from the home (rel-1-0-10:GAP-0142).
	members := archiveNamedMembers(facts)
	for _, full := range hookpaths.ArchiveExtractionFolders(command, facts.CWD, home) {
		full = path.Clean(filepath.ToSlash(full))
		if reaches(full) {
			return true
		}
		for _, member := range members {
			if reaches(path.Join(full, member)) {
				return true
			}
		}
	}
	return false
}

// archiveTarValueLetters are the tar short options whose value is the next
// word (or the rest of a dashed cluster).
const archiveTarValueLetters = "fCTXbHIKLNVg"

// archiveTarValueOptions are the tar long options whose value is the next
// word when it is not attached.
var archiveTarValueOptions = map[string]bool{
	"--file": true, "--directory": true, "--exclude": true, "--files-from": true, "--exclude-from": true,
	"--transform": true, "--xform": true, "--owner": true, "--group": true, "--mode": true, "--mtime": true,
	"--format": true, "--use-compress-program": true, "--strip-components": true, "--newer": true,
	"--after-date": true, "--label": true, "--blocking-factor": true, "--record-size": true,
}

// archiveNamedMembers lists the relative members a tar extraction onto disk
// (not -t, not -O/--to-stdout) or an unzip extraction (not -l, -p, -t, -Z)
// names: the words that are no option, option value or archive.
func archiveNamedMembers(facts actionfacts.Facts) []string {
	var members []string
	add := func(word string) {
		if word != "" && !strings.HasPrefix(word, "/") && !strings.HasPrefix(word, "-") {
			members = append(members, path.Clean(word))
		}
	}
	for _, command := range facts.Commands {
		argv := command.Argv
		if len(argv) < 2 {
			continue
		}
		switch path.Base(strings.ToLower(command.Program)) {
		case "tar", "gtar", "bsdtar":
			extract, stdout := false, false
			var pending int
			var operands []string
			for index, word := range argv[1:] {
				switch {
				case pending > 0:
					pending--
				case strings.HasPrefix(word, "--"):
					name, _, attached := strings.Cut(word, "=")
					switch name {
					case "--extract", "--get":
						extract = true
					case "--to-stdout", "--list", "--to-command":
						stdout = true
					}
					if !attached && archiveTarValueOptions[name] {
						pending++
					}
				case strings.HasPrefix(word, "-") && len(word) > 1 || index == 0:
					letters := strings.TrimPrefix(word, "-")
					for at := 0; at < len(letters); at++ {
						letter := letters[at]
						switch letter {
						case 'x':
							extract = true
						case 'O', 't':
							stdout = true
						}
						if strings.IndexByte(archiveTarValueLetters, letter) >= 0 {
							if strings.HasPrefix(word, "-") && at+1 < len(letters) {
								break
							}
							pending++
						}
					}
				default:
					operands = append(operands, word)
				}
			}
			if extract && !stdout {
				for _, operand := range operands {
					add(operand)
				}
			}
		case "unzip":
			archive, value, excluding, listing := "", false, false, false
			var named []string
			for _, word := range argv[1:] {
				switch {
				case value:
					value = false
				case word == "-d":
					value = true
				case word == "-x":
					// The exclusion list: no more members.
					excluding = true
				case strings.HasPrefix(word, "-"):
					listing = listing || strings.ContainsAny(word, "lptZ")
				case archive == "":
					archive = word
				case !excluding:
					named = append(named, word)
				}
			}
			if !listing {
				for _, word := range named {
					add(word)
				}
			}
		}
	}
	return members
}
