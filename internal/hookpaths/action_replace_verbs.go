// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Replace verbs: mv, install and sed -i remove the name an operand holds and
// create a new file under it. A name that is a hard link of a protected file
// (or a symlink to a file) is replaced; the protected inode is not written
// (rel-1-0-10 GAP-0293 review F7). Only the entry matters, as with touch -h.
// A name that is itself a protected path, an operand under the .ssh folder,
// or a symlink to a directory (mv follows it) is not covered: the normal
// readings judge it.

// replaceVerbSafe reports the bounded statement of one replace verb whose
// every operand entry is a name that holds nothing protected: ordinary, a
// hard link of a protected file, or a symlink to a file. The operands go
// through the one word resolver.
func replaceVerbSafe(command, cwd, home string) bool {
	return replaceVerbSafeIn(command, cwd, home, CurrentShellStartup())
}

func replaceVerbSafeIn(command, cwd, home string, startup ShellStartup) bool {
	if !filepath.IsAbs(cwd) || home == "" || actionWindowsHome(home) ||
		!strings.Contains(command, "mv") && !strings.Contains(command, "install") && !strings.Contains(command, "sed") {
		return false
	}
	call, values, ok := entryOnlyStatement(command, cwd, home)
	if !ok || len(call.Args) < 3 {
		return false
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed {
		return false
	}
	name := programBase(program)
	words, ok := replaceVerbOperandWords(name, call.Args[1:], home)
	if !ok || startup.mayChange(name) {
		return false
	}
	options := shellGlobOptionsForCall(command, startup)
	var operands []string
	for _, word := range words {
		if !noDereferenceTouchLiteralWord(word) && (len(word.Parts) != 1 || actionSoleParameter(word) == "") {
			return false
		}
		resolved := resolveShellWord(word, values, cwd, options, nil)
		if resolved.uncertain != "" {
			return false
		}
		operands = append(operands, resolved.candidates...)
		if len(operands) > 1024 {
			return false
		}
	}
	if len(operands) == 0 {
		return false
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	memo := NewTargetMemo()
	for _, operand := range operands {
		path := OperandPath(operand, cwd)
		parent, known := memo.resolveWriteTarget(filepath.Dir(path))
		if !known {
			return false
		}
		entry := filepath.Join(parent, filepath.Base(path))
		if protected.has(entry) || samePathName(entry, ssh) ||
			samePathName(parent, ssh) || strings.HasPrefix(parent, ssh+string(filepath.Separator)) {
			return false
		}
		info, err := pathLstat(entry)
		switch {
		case err != nil:
			if !errors.Is(err, fs.ErrNotExist) {
				return false
			}
		case info.Mode()&os.ModeSymlink != 0:
			// mv replaces a symlink everywhere, but what install and sed -i
			// do with a symlink destination differs between implementations
			// (GAP-0389 and the command-link tests pin them blocked): only a
			// hard-link name is proved for them.
			if name != "mv" && name != "gmv" {
				return false
			}
			if target, serr := pathStat(entry); serr == nil && target.IsDir() {
				return false
			}
		case info.IsDir():
			return false
		}
	}
	return true
}

// replaceVerbOperandWords splits the arguments of one replace verb into its
// file operand words with the bounded option grammar the proof knows. An
// option outside it (a target directory, a backup, following symlinks)
// leaves the call to the normal readings.
func replaceVerbOperandWords(program string, args []*syntax.Word, home string) ([]*syntax.Word, bool) {
	static := func(word *syntax.Word) (string, bool) { return StaticWord(word, home) }
	var operands []*syntax.Word
	options := true
	switch program {
	case "mv", "gmv":
		for _, word := range args {
			text, fixed := static(word)
			if options && fixed && strings.HasPrefix(text, "-") && text != "-" {
				if text == "--" {
					options = false
					continue
				}
				if strings.HasPrefix(text, "--") || strings.Trim(text[1:], "fnvTui") != "" {
					return nil, false
				}
				continue
			}
			operands = append(operands, word)
		}
		return operands, len(operands) >= 2
	case "install", "ginstall":
		for i := 0; i < len(args); i++ {
			word := args[i]
			text, fixed := static(word)
			if options && fixed && strings.HasPrefix(text, "-") && text != "-" {
				switch {
				case text == "--":
					options = false
				case text == "-m":
					if i+1 >= len(args) {
						return nil, false
					}
					i++
				case strings.HasPrefix(text, "-m") && !strings.HasPrefix(text, "--"):
				case !strings.HasPrefix(text, "--") && strings.Trim(text[1:], "DvCp") == "":
				default:
					return nil, false
				}
				continue
			}
			operands = append(operands, word)
		}
		return operands, len(operands) >= 2
	case "sed", "gsed":
		inPlace, haveScript := false, false
		for i := 0; i < len(args); i++ {
			word := args[i]
			text, fixed := static(word)
			if options && fixed && strings.HasPrefix(text, "-") && text != "-" {
				switch {
				case text == "--":
					options = false
				case text == "--in-place" || strings.HasPrefix(text, "--in-place="):
					inPlace = true
				case text == "--follow-symlinks" || strings.HasPrefix(text, "--") && text != "--regexp-extended" && text != "--quiet" && text != "--silent" && text != "--separate" && text != "--null-data":
					return nil, false
				case text == "-e":
					if i+1 >= len(args) {
						return nil, false
					}
					i++
					// The script must be fixed text that is read in full and
					// holds no command that writes or runs (GAP-0377).
					if script, fixed := static(args[i]); !fixed || !sedScriptReplaceOnly(script) {
						return nil, false
					}
					haveScript = true
				case strings.HasPrefix(text, "-i"):
					inPlace = true
				case strings.HasPrefix(text, "--"):
				case strings.Trim(text[1:], "Ernsz") == "":
				default:
					return nil, false
				}
				continue
			}
			if !haveScript {
				if script, fixed := static(word); !fixed || !sedScriptReplaceOnly(script) {
					return nil, false
				}
				haveScript = true
				continue
			}
			operands = append(operands, word)
		}
		return operands, inPlace && len(operands) >= 1
	}
	return nil, false
}
