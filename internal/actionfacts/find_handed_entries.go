// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"regexp"
	"strings"
)

// HandedEntries is what the programs a find -exec/-execdir/-ok/-okdir or an
// xargs runs do with the names they are handed (GAP-2122).
type HandedEntries struct {
	// MayChange is set when a program may write or remove a handed entry:
	// a shell, a wrapper such as sudo or env, or a writer such as
	// truncate, sed -i or sort -o.
	MayChange bool
	// Outputs are the files a copy-out program (cp or rsync to a
	// destination, tar -c or zip into an archive, python3 -m json.tool
	// into a file) writes while it only reads the handed entries. The
	// caller judges them: a copy into protected state changes it.
	Outputs []string
}

// Writes reports a hand-off that writes anything: a handed entry or a
// copy-out output.
func (h HandedEntries) Writes() bool { return h.MayChange || len(h.Outputs) != 0 }

func (h *HandedEntries) add(other HandedEntries) {
	h.MayChange = h.MayChange || other.MayChange
	h.Outputs = append(h.Outputs, other.Outputs...)
}

// findEmbeddedReaders are programs that, handed file names, only read
// them (or change only modes, owners or times: chmod, chown, chgrp,
// touch, judged on their own), whatever their arguments.
var findEmbeddedReaders = map[string]struct{}{
	"basename": {}, "b2sum": {}, "cat": {}, "cksum": {}, "cmp": {}, "diff": {},
	"dirname": {}, "du": {}, "echo": {}, "egrep": {}, "fgrep": {}, "file": {},
	"grep": {}, "head": {}, "less": {}, "ls": {}, "md5": {}, "md5sum": {},
	"more": {}, "od": {}, "printf": {}, "readlink": {}, "realpath": {},
	"rg": {}, "sha1sum": {}, "sha224sum": {}, "sha256sum": {}, "sha384sum": {},
	"sha512sum": {}, "shasum": {}, "stat": {}, "strings": {}, "tail": {},
	"test": {}, "[": {}, "true": {}, "false": {}, "wc": {},
	"jq": {}, "cut": {}, "column": {}, "nl": {}, "tac": {}, "rev": {},
	"chmod": {}, "chown": {}, "chgrp": {}, "touch": {},
}

// FindEmbeddedCommandMayChange reports a find argv with an -exec, -execdir,
// -ok or -okdir program that may change the entries it is handed or
// copies them out (GAP-2122).
func FindEmbeddedCommandMayChange(argv []string) bool {
	return FindHandedEntries(argv).Writes()
}

// FindHandedEntries reads every -exec, -execdir, -ok and -okdir program of
// a find argv. {} (alone or inside a word) is a handed entry.
func FindHandedEntries(argv []string) HandedEntries {
	var result HandedEntries
	for i := 1; i+1 < len(argv); i++ {
		action := argv[i]
		switch action {
		case "-exec", "-execdir", "-ok", "-okdir":
		default:
			continue
		}
		end := i + 1
		for end < len(argv) && argv[end] != ";" && argv[end] != "+" {
			end++
		}
		result.add(handedEntriesOf(argv[i+1:end], action == "-execdir" || action == "-okdir"))
		i = end
	}
	return result
}

// XargsHandedEntries reads the program words of an xargs (the program and
// its arguments). xargs appends the names it reads to them, or with -I R
// puts one in place of each R.
func XargsHandedEntries(words []string, replace string) HandedEntries {
	if len(words) == 0 {
		return HandedEntries{} // xargs runs echo
	}
	handed := make([]string, 0, len(words)+1)
	for _, word := range words {
		if replace != "" {
			word = strings.ReplaceAll(word, replace, "{}")
		}
		handed = append(handed, word)
	}
	if replace == "" {
		handed = append(handed, "{}")
	}
	return handedEntriesOf(handed, false)
}

// handedEntriesOf judges one program and its arguments. inEntryDir is set
// for -execdir/-okdir, which run in the directory of the entry, so a
// relative output lands next to it.
func handedEntriesOf(words []string, inEntryDir bool) HandedEntries {
	mayChange := HandedEntries{MayChange: true}
	if len(words) == 0 {
		return mayChange
	}
	program := strings.ToLower(words[0][strings.LastIndex(words[0], "/")+1:])
	args := words[1:]
	if _, reader := findEmbeddedReaders[program]; reader {
		return HandedEntries{}
	}
	var only bool
	switch program {
	case "timeout", "nice":
		// `timeout 5 PROGRAM ...`, `nice -n 5 PROGRAM ...` run PROGRAM with
		// the same words: it is judged (GAP-2404).
		if rest, ok := runnerProgramWords(program, args); ok {
			return handedEntriesOf(rest, inEntryDir)
		}
		return mayChange
	case "sh", "bash", "dash", "ksh", "mksh", "ash":
		// `bash -n {}` reads the script and runs none of it (GAP-2404).
		only = shellOnlyParses(args)
	case "uniq":
		only = len(handedOperands(args, "fsw")) <= 1
	case "xxd":
		// xxd INFILE OUTFILE rewrites OUTFILE (GAP-2302).
		only = !xxdWritesOutput(args)
	case "sort":
		only = sortOnlyPrints(args)
	case "sed":
		only = sedOnlyPrints(args)
	case "awk", "gawk", "mawk", "nawk":
		only = awkOnlyPrints(args)
	case "python", "python3":
		return jsonToolHandedEntries(args, inEntryDir)
	case "cp", "rsync":
		return copyHandedEntries(program, args, inEntryDir)
	case "tar":
		return tarHandedEntries(args, inEntryDir)
	case "zip":
		return zipHandedEntries(args, inEntryDir)
	}
	if only {
		return HandedEntries{}
	}
	return mayChange
}

// runnerProgramWords returns the program words a timeout or nice runs:
// after its options (and their values) and, for timeout, the duration. ok
// is false for an option it does not know.
func runnerProgramWords(program string, args []string) ([]string, bool) {
	index := 0
loop:
	for index < len(args) && strings.HasPrefix(args[index], "-") && args[index] != "-" {
		arg := args[index]
		switch {
		case arg == "--":
			index++
			break loop
		case program == "timeout" && (arg == "--preserve-status" || arg == "--foreground" ||
			arg == "-v" || arg == "--verbose" || strings.HasPrefix(arg, "--signal=") ||
			strings.HasPrefix(arg, "--kill-after=") || len(arg) > 2 && (arg[:2] == "-s" || arg[:2] == "-k")):
		case program == "timeout" && (arg == "-s" || arg == "-k"):
			index++
		case program == "nice" && arg == "-n":
			index++
		case program == "nice" && (strings.HasPrefix(arg, "--adjustment=") ||
			len(arg) > 2 && arg[:2] == "-n" || strings.Trim(arg[1:], "0123456789") == ""):
		default:
			return nil, false
		}
		index++
	}
	if program == "timeout" {
		if index >= len(args) {
			return nil, false
		}
		index++ // the duration
	}
	if index >= len(args) {
		return nil, false
	}
	return args[index:], true
}

// shellOnlyParses reports the arguments of a POSIX shell that reads its
// script without running it: a -n (noexec) option among its leading
// single-letter options, none of -c, -i or -o, and no +option or long
// option that could turn noexec off or run code.
func shellOnlyParses(args []string) bool {
	noexec, options := false, true
	for _, arg := range args {
		if strings.HasPrefix(arg, "+") || strings.HasPrefix(arg, "--") {
			return false
		}
		if options && len(arg) > 1 && arg[0] == '-' {
			letters := arg[1:]
			if strings.Trim(letters, "abefhkmnpstuvxBCEHPT") != "" || strings.ContainsAny(letters, "ci") {
				return false
			}
			noexec = noexec || strings.ContainsRune(letters, 'n')
			continue
		}
		options = false
	}
	return noexec
}

// handedOperands are the words that are not options or option values;
// valueLetters are the short options that take the next word (or the
// rest of the word).
func handedOperands(args []string, valueLetters string) []string {
	var operands []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			return append(operands, args[i+1:]...)
		case strings.HasPrefix(arg, "--"):
		case strings.HasPrefix(arg, "-") && arg != "-":
			for at, letter := range arg[1:] {
				if strings.ContainsRune(valueLetters, letter) {
					if at == len(arg)-2 {
						i++
					}
					break
				}
			}
		default:
			operands = append(operands, arg)
		}
	}
	return operands
}

// sortOnlyPrints reports a sort with no -o/--output file and no
// compression program.
func sortOnlyPrints(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			return true
		case strings.HasPrefix(arg, "--"):
			name, _, attached := strings.Cut(arg, "=")
			switch name {
			case "--output", "--compress-program", "--files0-from":
				return false
			case "--key", "--field-separator", "--buffer-size", "--temporary-directory",
				"--parallel", "--batch-size", "--sort", "--random-source":
				if !attached {
					i++
				}
			}
		case strings.HasPrefix(arg, "-") && arg != "-":
			for at, letter := range arg[1:] {
				if letter == 'o' {
					return false
				}
				if strings.ContainsRune("kStT", letter) {
					if at == len(arg)-2 {
						i++
					}
					break
				}
			}
		}
	}
	return true
}

// sedSafeScript is a sed script of addresses (line numbers, $, /regex/)
// and the print, quit, line-number and next commands only: no w/W file
// write, no e command, no s///w or s///e.
var sedSafeScript = regexp.MustCompile(`^(?:[0-9$,;!{}=pPqQnN \t\n+~]|/(?:[^/\\]|\\.)*/)*$`)

// sedOnlyPrints reports a sed with no in-place edit and only safe scripts.
func sedOnlyPrints(args []string) bool {
	scripted := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			i = len(args)
		case arg == "-e" || arg == "--expression":
			if i+1 >= len(args) || !sedSafeScript.MatchString(args[i+1]) {
				return false
			}
			scripted = true
			i++
		case strings.HasPrefix(arg, "--expression="):
			if !sedSafeScript.MatchString(arg[len("--expression="):]) {
				return false
			}
			scripted = true
		case strings.HasPrefix(arg, "--"):
			switch arg {
			case "--quiet", "--silent", "--regexp-extended", "--separate", "--null-data",
				"--posix", "--unbuffered", "--debug", "--sandbox":
			default:
				return false
			}
		case strings.HasPrefix(arg, "-") && arg != "-":
			if strings.Trim(arg[1:], "nErsuz") != "" {
				return false // -i, -I, -f, -l, -e in a cluster, unknown
			}
		default:
			if !scripted {
				if !sedSafeScript.MatchString(arg) {
					return false
				}
				scripted = true
			}
		}
	}
	return scripted
}

// awkWrite is a print or printf to a file or a pipe in an awk program.
var awkWrite = regexp.MustCompile(`\bprintf?\b[^;{}]*>`)

// awkOnlyPrints reports an awk whose program, given on the command line,
// runs no command and writes no file.
func awkOnlyPrints(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-F" || arg == "-v":
			i++
		case strings.HasPrefix(arg, "-F") || strings.HasPrefix(arg, "-v"):
		case arg == "--":
			if i+1 >= len(args) {
				return false
			}
			return awkProgramOnlyPrints(args[i+1])
		case strings.HasPrefix(arg, "-") && arg != "-":
			return false // -f progfile, -i/--include, -E, unknown
		default:
			return awkProgramOnlyPrints(arg)
		}
	}
	return false
}

func awkProgramOnlyPrints(program string) bool {
	return !strings.Contains(program, "system") && !strings.ContainsAny(program, "|@") &&
		!awkWrite.MatchString(program)
}

// jsonToolHandedEntries reads python3 -m json.tool [options] INFILE
// [OUTFILE].
func jsonToolHandedEntries(args []string, inEntryDir bool) HandedEntries {
	if len(args) < 2 || args[0] != "-m" || args[1] != "json.tool" {
		return HandedEntries{MayChange: true}
	}
	var operands []string
	for i := 2; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "--sort-keys", "--compact", "--no-ensure-ascii", "--json-lines", "--tab", "--no-indent":
		case "--indent":
			i++
		default:
			if strings.HasPrefix(arg, "-") {
				return HandedEntries{MayChange: true}
			}
			operands = append(operands, arg)
		}
	}
	switch {
	case len(operands) == 1 && strings.Contains(operands[0], "{}"):
		return HandedEntries{}
	case len(operands) == 2 && strings.Contains(operands[0], "{}"):
		return copyOutputs(inEntryDir, operands[1])
	}
	return HandedEntries{MayChange: true}
}

// copyHandedEntries reads cp and rsync: the handed entries are sources
// unless one is the destination (the last operand, or the -t value).
func copyHandedEntries(program string, args []string, inEntryDir bool) HandedEntries {
	var operands []string
	target := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			operands = append(operands, args[i+1:]...)
			i = len(args)
		case strings.HasPrefix(arg, "--"):
			name, value, attached := strings.Cut(arg, "=")
			switch {
			case program == "cp" && name == "--target-directory":
				if !attached {
					if i+1 >= len(args) {
						return HandedEntries{MayChange: true}
					}
					i++
					value = args[i]
				}
				target = value
			case program == "rsync" && (name == "--remove-source-files" || name == "--rsh" && !attached):
				return HandedEntries{MayChange: true}
			}
		case strings.HasPrefix(arg, "-") && arg != "-":
			letters := arg[1:]
			for at, letter := range letters {
				value := ""
				switch {
				case program == "cp" && letter == 't':
					value = letters[at+1:]
					if value == "" {
						if i+1 >= len(args) {
							return HandedEntries{MayChange: true}
						}
						i++
						value = args[i]
					}
					target = value
				case program == "cp" && letter == 'S', program == "rsync" && strings.ContainsRune("eBT", letter):
					if letters[at+1:] == "" {
						i++
					}
				default:
					continue
				}
				break
			}
		default:
			operands = append(operands, arg)
		}
	}
	if target == "" {
		if len(operands) < 2 {
			return HandedEntries{MayChange: true}
		}
		target = operands[len(operands)-1]
	}
	return copyOutputs(inEntryDir, target)
}

// tarHandedEntries reads a tar that creates or lists an archive of the
// handed entries; any other mode, or an option that runs a program,
// may change them.
func tarHandedEntries(args []string, inEntryDir bool) HandedEntries {
	creates, archive := false, ""
	letters := func(cluster string, i *int) bool {
		for at, letter := range cluster {
			switch {
			case letter == 'c' || letter == 't':
				creates = true
			case letter == 'f':
				archive = cluster[at+1:]
				if archive == "" {
					if *i+1 >= len(args) {
						return false
					}
					*i++
					archive = args[*i]
				}
				return true
			case strings.ContainsRune("vzjJpPhSO", letter):
			default:
				return false // x, r, u, A, -C/-T/-X/-I values, unknown
			}
		}
		return true
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case i == 0 && !strings.HasPrefix(arg, "-"):
			if !letters(arg, &i) {
				return HandedEntries{MayChange: true}
			}
		case strings.HasPrefix(arg, "--"):
			name, value, attached := strings.Cut(arg, "=")
			switch name {
			case "--create", "--list":
				creates = true
			case "--verbose", "--gzip", "--bzip2", "--xz", "--preserve-permissions", "--dereference":
			case "--file":
				if !attached {
					if i+1 >= len(args) {
						return HandedEntries{MayChange: true}
					}
					i++
					value = args[i]
				}
				archive = value
			default:
				return HandedEntries{MayChange: true}
			}
		case strings.HasPrefix(arg, "-") && arg != "-":
			if !letters(arg[1:], &i) {
				return HandedEntries{MayChange: true}
			}
		}
	}
	if !creates || strings.Contains(archive, "{}") {
		return HandedEntries{MayChange: true}
	}
	if archive == "" || archive == "-" {
		return HandedEntries{}
	}
	return copyOutputs(inEntryDir, archive)
}

// zipHandedEntries reads zip [flags] ARCHIVE ENTRIES: the archive is the
// output; -m moves (deletes) the entries.
func zipHandedEntries(args []string, inEntryDir bool) HandedEntries {
	var operands []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && arg != "-" {
			if strings.Trim(arg[1:], "rqjyvXD0123456789") != "" {
				return HandedEntries{MayChange: true}
			}
			continue
		}
		operands = append(operands, arg)
	}
	if len(operands) < 2 {
		return HandedEntries{MayChange: true}
	}
	return copyOutputs(inEntryDir, operands[0])
}

// copyOutputs is a copy-out to output: a handed entry as the output, a
// spelling the shell would still expand, or a relative output beside the
// entry (-execdir) may change the entries.
func copyOutputs(inEntryDir bool, output string) HandedEntries {
	if output == "" || strings.Contains(output, "{}") || strings.ContainsAny(output, "$`*?[~") ||
		inEntryDir && !strings.HasPrefix(output, "/") {
		return HandedEntries{MayChange: true}
	}
	return HandedEntries{Outputs: []string{output}}
}
