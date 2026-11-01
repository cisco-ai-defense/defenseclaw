// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path/filepath"
	"strings"
)

// embeddedProgram is one program a find -exec/-execdir/-ok/-okdir or an
// xargs runs, with every word that holds a handed entry ({} or the xargs
// -I string) left out: what is left is what the program does to the paths
// it names itself (GAP-2304).
type embeddedProgram struct {
	argv []string
	// parent is the index of each argv word in the find or xargs argv.
	parent []int
	// inEntryDir is set for -execdir/-okdir, which run in the directory of
	// the entry, so a relative path is not relative to the working
	// directory.
	inEntryDir bool
}

func findEmbeddedPrograms(argv []string) []embeddedProgram {
	var programs []embeddedProgram
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
		if end < len(argv) {
			program := embeddedProgram{inEntryDir: action == "-execdir" || action == "-okdir"}
			for index := i + 1; index < end; index++ {
				if strings.Contains(argv[index], "{}") {
					continue
				}
				program.argv = append(program.argv, argv[index])
				program.parent = append(program.parent, index)
			}
			programs = append(programs, program)
		}
		i = end
	}
	return programs
}

func xargsEmbeddedPrograms(argv []string) []embeddedProgram {
	start, replace, known := XargsProgram(argv)
	if !known || start >= len(argv) {
		return nil
	}
	var program embeddedProgram
	for index := start; index < len(argv); index++ {
		if replace != "" && strings.Contains(argv[index], replace) {
			continue
		}
		program.argv = append(program.argv, argv[index])
		program.parent = append(program.parent, index)
	}
	return []embeddedProgram{program}
}

// XargsProgram reads the options of an xargs argv: start is the index of
// the program word (len(argv) when xargs runs its default echo) and
// replace the -I/-i/--replace string. known is false for an option it does
// not know, which may hide the program.
func XargsProgram(argv []string) (start int, replace string, known bool) {
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		switch {
		case argument == "--":
			return index + 1, replace, true
		case !strings.HasPrefix(argument, "-") || argument == "-":
			return index, replace, true
		case strings.HasPrefix(argument, "--"):
			name, value, attached := strings.Cut(argument, "=")
			switch name {
			case "--null", "--no-run-if-empty", "--verbose", "--interactive", "--exit", "--open-tty",
				"--eof", "--max-lines":
			case "--replace":
				replace = "{}"
				if attached {
					replace = value
				}
			case "--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars", "--process-slot-var":
				if !attached {
					index++
				}
			default:
				return 0, "", false
			}
		default:
			letters := argument[1:]
			for at := 0; at < len(letters); at++ {
				switch letters[at] {
				case '0', 'r', 't', 'p', 'x', 'o':
				case 'i':
					// The value is optional and only attached.
					replace = "{}"
					if letters[at+1:] != "" {
						replace = letters[at+1:]
					}
					at = len(letters)
				case 'e', 'l':
					at = len(letters)
				case 'I':
					if letters[at+1:] != "" {
						replace = letters[at+1:]
					} else if index+1 < len(argv) {
						index++
						replace = argv[index]
					}
					at = len(letters)
				case 'a', 'd', 'E', 'L', 'n', 'P', 's':
					if at == len(letters)-1 {
						index++
					}
					at = len(letters)
				default:
					return 0, "", false
				}
			}
		}
	}
	return len(argv), replace, true
}

// IsEmbeddedProgramCommand reports a command that a find -exec/-execdir/
// -ok/-okdir or an xargs runs, read from its own words. Such a command is
// attached only when its own analysis is complete (classifyEmbeddedPrograms),
// so its facts are exact for the paths it names even when the find or
// xargs around it stays partial.
func IsEmbeddedProgramCommand(command CommandFact) bool {
	for _, wrapper := range command.Wrappers {
		switch commandProgram(wrapper.Executable) {
		case "find", "xargs":
			return true
		}
	}
	return false
}

// classifyEmbeddedPrograms judges the program of a find -exec/-execdir/
// -ok/-okdir or an xargs on the paths it names itself, as if it ran
// directly (GAP-2304): `find /tmp -maxdepth 0 -exec rm -rf ~/.defenseclaw/hooks \;`,
// `find ~/proj -name '*.log' -exec rm -f {} ~/.defenseclaw/config.yaml \;`
// and `echo | xargs rm -rf ~/.defenseclaw/hooks` remove what rm -rf names.
// The words holding a handed entry are left out (the find case judges the
// entries). Only a program whose own analysis is complete is attached, as
// a child command of the find or xargs, so it adds exact facts and never
// changes the parse status; a relative path of an -execdir/-okdir program
// is not relative to the working directory, so such a program is skipped.
func classifyEmbeddedPrograms(out *parseOutput, wrapperDepth int) {
	if wrapperDepth >= maxWrapperDepth {
		return
	}
	outer := cloneCommands(out.commands)
	for _, command := range outer {
		if !command.ArgvComplete || command.Effect != EffectExecute || len(command.Argv) < 2 {
			continue
		}
		var programs []embeddedProgram
		switch command.Program {
		case "find":
			programs = findEmbeddedPrograms(command.Argv)
		case "xargs":
			programs = xargsEmbeddedPrograms(command.Argv)
		default:
			continue
		}
		for _, program := range programs {
			if len(program.argv) < 2 {
				continue
			}
			child := analyzeStructuredArgv(program.argv, out.nextID, wrapperDepth+1, DialectPOSIX)
			child.dialect = DialectPOSIX
			carryEmbeddedLiteralTildes(&child, command, program)
			classifyOutputAt(&child, wrapperDepth+1)
			if child.status != StatusComplete || len(child.issues) != 0 || len(child.commands) == 0 ||
				program.inEntryDir && embeddedHasRelativePath(child) {
				continue
			}
			for i := range child.commands {
				if child.commands[i].ParentCommandID == 0 {
					child.commands[i].ParentCommandID = command.ID
				}
				child.commands[i].Wrappers = append(
					[]WrapperFact{{Executable: command.Executable, Argv: cloneSlice(command.Argv)}},
					child.commands[i].Wrappers...,
				)
			}
			child.dialect = out.dialect
			status := out.status
			out.mergeNested(child)
			out.status = status
		}
	}
}

func embeddedHasRelativePath(child parseOutput) bool {
	for _, fact := range child.paths {
		if !filepath.IsAbs(fact.Value) && !strings.HasPrefix(fact.Value, "/") &&
			!strings.HasPrefix(fact.Value, "~") {
			return true
		}
	}
	return false
}

// carryEmbeddedLiteralTildes marks a word the find or xargs got with a
// quoted or escaped tilde as the literal name in the program's commands.
func carryEmbeddedLiteralTildes(child *parseOutput, parent CommandFact, program embeddedProgram) {
	if len(parent.Arguments) != len(parent.Argv) {
		return
	}
	for i := range child.commands {
		command := &child.commands[i]
		offset := len(program.argv) - len(command.Argv)
		if offset < 0 || len(command.Arguments) != len(command.Argv) {
			continue
		}
		for j := range command.Arguments {
			if command.Argv[j] != program.argv[offset+j] {
				break
			}
			if parent.Arguments[program.parent[offset+j]].literalTilde {
				command.Arguments[j].literalTilde = true
			}
		}
	}
}
