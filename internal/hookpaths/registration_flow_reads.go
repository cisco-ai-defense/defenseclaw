// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// registrationFlowText is the command text the flow net of the registration
// reader (registrationFlowMembers) matches registered names in: the command
// with the words that only name a file for it to be read blanked out
// (rel-1-0-10:GAP-0104). Those are
//   - the words of a plain read statement (actionPlainReadStatements: a
//     system reader such as sha256sum, shasum, stat or cmp, at the top of the
//     call, in an && or || list, or as a stage of a pipeline of readers, in a
//     call with no $_, assignment, function, declaration or rebound reader
//     name), and
//   - the sources of a cp and the members of a tar create
//     (registrationCopySourceWords).
//
// The net counted every registered file named anywhere in a call once any
// part of the call could write, so `cmp -s a ~/.claude/settings.json && echo
// SAME > /tmp/x` or `cp ~/.codex/config.toml /tmp/bak/` was read as a write
// of the config. Only words are blanked, never a redirect: a redirect target,
// a cp destination, a tar archive and every word of any other statement keep
// the old whole-text match, so a write into a registered file is named as
// before.
func registrationFlowText(file *syntax.File, command, home string, protected protectedFiles) string {
	var spans [][2]int
	add := func(word *syntax.Word) {
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start >= 0 && end <= len(command) && start < end && registrationPlainWord(word) {
			spans = append(spans, [2]int{start, end})
		}
	}
	for stmt := range actionPlainReadStatements(file, home) {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			continue
		}
		for _, word := range call.Args[1:] {
			add(word)
		}
	}
	for _, word := range registrationCopySourceWords(file, home, protected) {
		add(word)
	}
	if len(spans) == 0 {
		return command
	}
	text := []byte(command)
	for _, span := range spans {
		for index := span[0]; index < span[1]; index++ {
			text[index] = ' '
		}
	}
	return string(text)
}

// registrationPlainWord reports a word whose text can do nothing but name a
// value: literal and quoted text and plain $name expansions. A command or
// process substitution runs a command of its own, and an expansion with an
// operator (${x:=v}) or an arithmetic one can assign a variable, so such a
// word is never blanked.
func registrationPlainWord(word *syntax.Word) bool {
	plain := true
	syntax.Walk(word, func(node syntax.Node) bool {
		if !plain {
			return false
		}
		switch node := node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp, *syntax.ExtGlob:
			plain = false
		case *syntax.ParamExp:
			plain = plain && !node.Excl && !node.Length && !node.Width && node.Index == nil &&
				node.Slice == nil && node.Repl == nil && node.Exp == nil && node.NestedParam == nil
		}
		return plain
	})
	return plain
}

// registrationCopySourceWords are the words that a cp or a tar create only
// reads, in the statements actionPlainReadStatements would read (the top of
// the call and && or || lists, not a pipeline, a background job, a negation
// or a substitution):
//   - cp SOURCE... DEST and cp -t DEST SOURCE...: each static source whose
//     landing in an absolute static destination (DEST itself, or
//     DEST/<source base> when DEST is a folder) is no registered file;
//   - tar -c[f ARCHIVE] MEMBER...: each static member (tar writes only the
//     archive, which stays in the text).
//
// The call must run the system program (no function, alias, hash or file
// written under its name, no $_ that hands its last word on, no assignment
// that can change what a bare name runs), and every option must be one the
// reader knows: an option it does not know may name another destination
// (cp --target-directory) or write or remove the sources (tar
// --remove-files), so it leaves the whole call in the text.
func registrationCopySourceWords(file *syntax.File, home string, protected protectedFiles) []*syntax.Word {
	if file == nil || !registrationCopyGuard(file, home) {
		return nil
	}
	var out []*syntax.Word
	var visit func(stmt *syntax.Stmt)
	visit = func(stmt *syntax.Stmt) {
		if stmt == nil || stmt.Background || stmt.Coprocess || stmt.Negated {
			return
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.BinaryCmd:
			if cmd.Op == syntax.AndStmt || cmd.Op == syntax.OrStmt {
				visit(cmd.X)
				visit(cmd.Y)
			}
		case *syntax.CallExpr:
			if len(cmd.Args) == 0 || len(cmd.Assigns) != 0 {
				return
			}
			call := cmd
			if wrapped, ok := actionReadOnlyWrappedCall(cmd, home); ok {
				call = wrapped
			}
			program, known := staticProgramWord(call.Args[0], home)
			if !known || strings.Contains(program, "\\") ||
				strings.Contains(program, "/") && !slices.Contains(readerDirectories, filepath.Dir(program)) {
				return
			}
			switch programBase(program) {
			case "cp", "gcp":
				out = append(out, registrationCopySources(call.Args[1:], home, protected)...)
			case "tar", "gtar", "bsdtar":
				out = append(out, registrationTarCreateMembers(call.Args[1:], home)...)
			}
		}
	}
	for _, stmt := range file.Stmts {
		visit(stmt)
	}
	return out
}

// registrationCopyGuard reports a call in which a cp or tar word is the
// system program and no word hands a source name on: no function or
// declaration, no rebound program name (actionRebindsReaderNames), no $_
// (the last word of the statement before, a source of a tar or the
// destination of a cp), and only lower-case scalar assignments other than
// path and fpath (PATH=/tmp/x changes what cp runs).
func registrationCopyGuard(file *syntax.File, home string) bool {
	if actionRebindsReaderNames(file, home) {
		return false
	}
	safe := true
	syntax.Walk(file, func(node syntax.Node) bool {
		if !safe {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl, *syntax.DeclClause:
			safe = false
		case *syntax.ParamExp:
			safe = node.Param == nil || node.Param.Value != "_"
		case *syntax.Assign:
			name := ""
			if node.Name != nil {
				name = node.Name.Value
			}
			safe = name != "" && name != "path" && name != "fpath" && !node.Append && node.Array == nil &&
				node.Index == nil && !strings.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		case *syntax.CallExpr:
			if len(node.Args) > 0 {
				program, known := staticProgramWord(node.Args[0], home)
				if !known || registrationFlowBuiltins[programBase(program)] && programBase(program) != "command" ||
					programBase(program) == "hash" {
					safe = false
				}
			}
		}
		return safe
	})
	return safe
}

// registrationCopyFlagLetters are the GNU and BSD cp short options that take
// no value and do not move the destination: archive, backup, no-dereference,
// force, -H, interactive, link, dereference, no-clobber, -P, preserve,
// recursive, symbolic link, no-target-directory, update, verbose,
// one-file-system.
const registrationCopyFlagLetters = "abdfHilLnPpRrsTuvx"

// registrationCopyLongFlags are the cp long options the source reader knows.
var registrationCopyLongFlags = map[string]bool{
	"--archive": true, "--backup": true, "--force": true, "--interactive": true, "--link": true,
	"--dereference": true, "--no-dereference": true, "--no-clobber": true, "--preserve": true,
	"--no-preserve": true, "--recursive": true, "--symbolic-link": true, "--no-target-directory": true,
	"--update": true, "--verbose": true, "--one-file-system": true, "--remove-destination": true,
	"--reflink": true, "--sparse": true, "--strip-trailing-slashes": true, "--attributes-only": true,
	"--target-directory": true, "--suffix": true,
}

// registrationCopySources returns the source words of a cp call (args: the
// words after the program) whose landing is no registered file, when every
// word is static and every option is known. --parents (the source path is
// rebuilt below the destination) gives none.
func registrationCopySources(args []*syntax.Word, home string, protected protectedFiles) []*syntax.Word {
	var operands []*syntax.Word
	var operandValues []string
	target, targetSet, noTarget := "", false, false
	optionsDone := false
	for index := 0; index < len(args); index++ {
		value, known := StaticWord(args[index], home)
		if !known || value == "" {
			return nil
		}
		switch {
		case optionsDone || value == "-" || !strings.HasPrefix(value, "-"):
			operands = append(operands, args[index])
			operandValues = append(operandValues, value)
		case value == "--":
			optionsDone = true
		case strings.HasPrefix(value, "--"):
			name, attached, hasValue := strings.Cut(value, "=")
			if !registrationCopyLongFlags[name] {
				return nil
			}
			switch name {
			case "--target-directory", "--suffix":
				if !hasValue {
					if index+1 >= len(args) {
						return nil
					}
					index++
					attached, known = StaticWord(args[index], home)
					if !known {
						return nil
					}
				}
				if name == "--target-directory" {
					target, targetSet = attached, true
				}
			case "--no-target-directory":
				noTarget = true
			}
		default:
			letters := value[1:]
			for at := 0; at < len(letters); at++ {
				letter := letters[at]
				if letter == 't' || letter == 'S' {
					rest := letters[at+1:]
					if rest == "" {
						if index+1 >= len(args) {
							return nil
						}
						index++
						rest, known = StaticWord(args[index], home)
						if !known {
							return nil
						}
					}
					if letter == 't' {
						target, targetSet = rest, true
					}
					break
				}
				if strings.IndexByte(registrationCopyFlagLetters, letter) < 0 {
					return nil
				}
				if letter == 'T' {
					noTarget = true
				}
			}
		}
	}
	sources, sourceValues := operands, operandValues
	if !targetSet {
		if len(operands) < 2 {
			return nil
		}
		target = operandValues[len(operandValues)-1]
		sources, sourceValues = operands[:len(operands)-1], operandValues[:len(operandValues)-1]
	}
	if target == "" || !filepath.IsAbs(filepath.FromSlash(target)) && !filepath.IsAbs(target) {
		return nil
	}
	destination := filepath.Clean(filepath.FromSlash(target))
	var out []*syntax.Word
	for index, source := range sources {
		value := sourceValues[index]
		if strings.ContainsAny(value, "*?[") {
			continue
		}
		landings := []string{destination}
		if !noTarget || targetSet {
			base := filepath.Base(filepath.Clean(filepath.FromSlash(value)))
			landings = append(landings, filepath.Join(destination, base))
		}
		lands := false
		for _, landing := range landings {
			for _, entry := range protected {
				if filepath.Clean(entry.path) == landing || strings.HasPrefix(entry.path, landing+string(filepath.Separator)) {
					lands = true
				}
			}
		}
		if !lands {
			out = append(out, source)
		}
	}
	return out
}

// registrationTarCreateLongFlags are the tar create options the member reader
// knows; each writes nothing but the archive.
var registrationTarCreateLongFlags = map[string]bool{
	"--create": true, "--gzip": true, "--bzip2": true, "--xz": true, "--zstd": true, "--verbose": true,
	"--preserve-permissions": true, "--numeric-owner": true, "--dereference": true, "--absolute-names": true,
	"--one-file-system": true, "--exclude-vcs": true, "--ignore-failed-read": true, "--auto-compress": true,
	"--exclude": true, "--owner": true, "--group": true, "--mtime": true, "--sort": true, "--format": true,
	"--file": true, "--directory": true, "--totals": true, "--sparse": true,
}

// registrationTarCreateMembers returns the member words of a tar create
// (args: the words after the program) when every word is known: one c mode
// and no other mode, -f ARCHIVE (local, not host:file, which runs a remote
// shell) and -C DIR. Their values stay in the text.
func registrationTarCreateMembers(args []*syntax.Word, home string) []*syntax.Word {
	var members []*syntax.Word
	create, values, optionsDone := false, 0, false
	for index, word := range args {
		value, known := StaticWord(word, home)
		if values > 0 {
			// The value of -f, -C or a long option: it stays in the text,
			// so a value only the shell knows ("$s/pre.tar") is kept as is.
			values--
			if known && strings.Contains(value, ":") {
				return nil
			}
			continue
		}
		if !known {
			return nil
		}
		switch {
		case optionsDone || value == "-" || !strings.HasPrefix(value, "-") && index != 0:
			if strings.ContainsAny(value, "*?[") {
				continue
			}
			members = append(members, word)
		case value == "--":
			optionsDone = true
		case strings.HasPrefix(value, "--"):
			name, attached, hasValue := strings.Cut(value, "=")
			if !registrationTarCreateLongFlags[name] {
				return nil
			}
			create = create || name == "--create"
			switch name {
			case "--file", "--directory", "--exclude", "--owner", "--group", "--mtime", "--sort", "--format":
				if !hasValue {
					values++
				} else if name == "--file" && strings.Contains(attached, ":") {
					return nil
				}
			}
		default:
			// A first word without a dash is the old bundled form (cvf).
			letters := strings.TrimPrefix(value, "-")
			for at := 0; at < len(letters); at++ {
				switch letters[at] {
				case 'c':
					if create {
						return nil
					}
					create = true
				case 'v', 'z', 'j', 'J', 'Z', 'p', 'h', 'P', 'a':
				case 'f', 'C':
					if rest := letters[at+1:]; rest != "" && value[0] == '-' {
						if letters[at] == 'f' && strings.Contains(rest, ":") {
							return nil
						}
						at = len(letters)
						continue
					}
					values++
				default:
					return nil
				}
			}
		}
	}
	if !create || values != 0 {
		return nil
	}
	return members
}
