// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// find expressions have their own operand grammar. In particular, a word
// following -name or -printf is data even when it spells -fprint.
func classifyFindOutputOperands(out *parseOutput, command *CommandFact) {
	argv := command.Argv
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch arg {
		case "-fls", "-fprint", "-fprint0", "-fprintf":
			if i+1 >= len(argv) || argv[i+1] == "" {
				out.markPartial(IssueUnknownOperandGrammar)
				return
			}
			i++
			addOperation(command, OperationWrite)
			appendCommandPath(out, command, PathAccessWrite, argv[i])
			if arg == "-fprintf" {
				if i+1 >= len(argv) {
					out.markPartial(IssueUnknownOperandGrammar)
					return
				}
				i++ // format, never a path
			}
		case "-amin", "-anewer", "-atime", "-cmin", "-cnewer", "-ctime",
			"-gid", "-group", "-ilname", "-iname", "-inum", "-ipath",
			"-iregex", "-links", "-lname", "-maxdepth", "-mindepth",
			"-mmin", "-mtime", "-name", "-newer", "-newermt", "-path",
			"-perm", "-printf", "-regex", "-size", "-type", "-uid",
			"-used", "-user", "-wholename", "-fstype", "-files0-from":
			if i+1 >= len(argv) {
				out.markPartial(IssueUnknownOperandGrammar)
				return
			}
			i++
		case "-exec", "-execdir", "-ok", "-okdir":
			for i+1 < len(argv) && argv[i+1] != ";" && argv[i+1] != "+" {
				i++
			}
			if i+1 >= len(argv) {
				out.markPartial(IssueUnknownOperandGrammar)
				return
			}
			i++
		}
	}
}

// gawk's -i/--include loads an extension; the shipped inplace extension
// rewrites every input file. File and source options supply the AWK program,
// not a destination. Unsupported option grammar remains partial.
func classifyAwkOutputOperands(out *parseOutput, command *CommandFact, program string) {
	// AWK source is a separate language. Its expression grammar can write
	// files or run commands; option and operand parsing cannot certify it.
	out.markPartial(IssueUnknownOperandGrammar)
	argv := command.Argv
	inplace := false
	programSupplied := false
	programSeen := false
	var files []string
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if !programSeen && arg == "--" {
			programSeen = true
			continue
		}
		if !programSeen && strings.HasPrefix(arg, "-") && arg != "-" {
			key, value, joined := strings.Cut(arg, "=")
			if !strings.HasPrefix(arg, "--") && len(arg) > 2 {
				switch arg[1] {
				case 'i', 'f', 'e', 'v', 'F', 'p', 'd':
					key, value, joined = arg[:2], arg[2:], true
				}
			}
			switch {
			case key == "-i" || key == "--include":
				if program != "gawk" {
					out.markPartial(IssueUnknownOperandGrammar)
				}
				if !joined && strings.HasPrefix(arg, "-i") && len(arg) > 2 {
					value, joined = arg[2:], true
				}
				if !joined {
					if i+1 >= len(argv) {
						out.markPartial(IssueUnknownOperandGrammar)
						return
					}
					i++
					value = argv[i]
				}
				if value == "inplace" {
					inplace = true
				} else {
					// An arbitrary extension may write its input files.
					out.markPartial(IssueUnknownOperandGrammar)
				}
			case key == "-f" || key == "--file" || key == "-e" || key == "--source",
				key == "-v" || key == "--assign", key == "-F" || key == "--field-separator":
				if !joined {
					if i+1 >= len(argv) {
						out.markPartial(IssueUnknownOperandGrammar)
						return
					}
					i++
					value = argv[i]
				}
				if value == "" {
					out.markPartial(IssueUnknownOperandGrammar)
					return
				}
				if key == "-f" || key == "--file" || key == "-e" || key == "--source" {
					programSupplied = true
				}
			case key == "-p" || key == "--profile" || key == "-d" ||
				key == "--dump-variables" || key == "--debug":
				if key == "-p" || key == "-d" {
					// GNU awk's short output options take an optional
					// attached file. The next argv word is the program.
					if value != "" {
						addOperation(command, OperationWrite)
						appendCommandPath(out, command, PathAccessWrite, value)
					}
				} else if joined && value != "" {
					addOperation(command, OperationWrite)
					appendCommandPath(out, command, PathAccessWrite, value)
				}
			case arg == "--posix" || arg == "--traditional" || arg == "--lint" ||
				arg == "--bignum" || arg == "--characters-as-bytes":
			default:
				out.markPartial(IssueUnknownOperandGrammar)
			}
			continue
		}
		if !programSeen && !programSupplied {
			programSeen = true
			continue
		}
		programSeen = true
		if !strings.Contains(arg, "=") {
			files = append(files, arg)
			appendCommandPath(out, command, PathAccessRead, arg)
		}
	}
	if !programSeen && !programSupplied {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if inplace {
		if len(files) == 0 {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		for _, target := range files {
			addOperation(command, OperationWrite)
			appendCommandPath(out, command, PathAccessWrite, target)
		}
	}
}

// uniq accepts at most INPUT and OUTPUT after its options. A single file
// operand is input; the second is the output file.
func classifyUniqOutputOperand(out *parseOutput, command *CommandFact) {
	argv := command.Argv
	var positionals []string
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			key, value, joined := strings.Cut(arg, "=")
			switch key {
			case "--skip-fields", "--skip-chars", "--check-chars":
				if !joined {
					if i+1 >= len(argv) {
						out.markPartial(IssueUnknownOperandGrammar)
						return
					}
					i++
					value = argv[i]
				}
				if value == "" {
					out.markPartial(IssueUnknownOperandGrammar)
				}
			case "--count", "--repeated", "--unique", "--ignore-case", "--zero-terminated",
				"--all-repeated", "--group", "--help", "--version":
				if joined && key != "--all-repeated" && key != "--group" {
					out.markPartial(IssueUnknownOperandGrammar)
				}
			default:
				out.markPartial(IssueUnknownOperandGrammar)
			}
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			for offset := 1; offset < len(arg); offset++ {
				switch arg[offset] {
				case 'c', 'd', 'D', 'u', 'i', 'z':
				case 'f', 's', 'w':
					if offset+1 == len(arg) {
						if i+1 >= len(argv) {
							out.markPartial(IssueUnknownOperandGrammar)
							return
						}
						i++
					}
					offset = len(arg)
				default:
					out.markPartial(IssueUnknownOperandGrammar)
				}
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	if len(positionals) > 0 && positionals[0] != "-" {
		appendCommandPath(out, command, PathAccessRead, positionals[0])
	}
	if len(positionals) > 1 && positionals[1] != "-" {
		addOperation(command, OperationWrite)
		appendCommandPath(out, command, PathAccessWrite, positionals[1])
	}
	if len(positionals) > 2 {
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

// An unmodeled program can still expose a static file-shaped output
// position. Keep its grammar partial and record the possible write, so a
// protected destination cannot be treated as a proven read-only argument.
func classifyUnknownOutputOperand(out *parseOutput, command *CommandFact) {
	for _, value := range UnknownOutputOptionTargets(command.Argv) {
		addOperation(command, OperationWrite)
		appendCommandPath(out, command, PathAccessWrite, value)
	}
}

// UnknownOutputOptionTargets are bounded possible file destinations of an
// unmodeled program. A caller may use these only as positive, conservative
// evidence; the program's full grammar is still unknown.
func UnknownOutputOptionTargets(argv []string) []string {
	var targets []string
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		key, value, joined := strings.Cut(arg, "=")
		if !strings.HasPrefix(arg, "--") && len(arg) > 2 &&
			(arg[:2] == "-o" || arg[:2] == "-O") {
			key, value, joined = arg[:2], strings.TrimPrefix(arg[2:], "="), true
		}
		switch key {
		case "--output", "--output-file", "--outfile", "--out", "-o", "-O":
			if !joined {
				if len(key) == 2 && len(arg) > 2 {
					value = arg[2:]
				} else if i+1 < len(argv) {
					i++
					value = argv[i]
				}
			}
			if value != "" && value != "-" {
				targets = append(targets, value)
			}
		}
	}
	return targets
}

// xxd reads INFILE and writes OUTFILE: `xxd INFILE OUTFILE` (and `xxd -r
// INFILE OUTFILE`) truncates and rewrites the second operand, so `xxd
// /dev/null FILE` empties FILE (GAP-2302). A single operand is only read.
func classifyXxdOperands(out *parseOutput, command *CommandFact) {
	positionals, ok := xxdPositionals(command.Argv[1:])
	if !ok {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if len(positionals) > 0 && positionals[0] != "-" {
		addOperation(command, OperationRead)
		appendCommandPath(out, command, PathAccessRead, positionals[0])
	}
	if len(positionals) > 1 && positionals[1] != "-" {
		addOperation(command, OperationWrite)
		appendCommandPath(out, command, PathAccessWrite, positionals[1])
	}
	if len(positionals) > 2 {
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

// xxdValueOptions are the xxd options that take a value, by the short
// letter and the long spellings xxd accepts (-c/-cols, -g/-groupsize,
// -l/-len, -o/-offset, -s/-seek, -n/-name, -R).
var xxdValueOptions = map[string]struct{}{
	"-c": {}, "-cols": {}, "-g": {}, "-groupsize": {}, "-l": {}, "-len": {},
	"-o": {}, "-offset": {}, "-s": {}, "-seek": {}, "-n": {}, "-name": {}, "-R": {},
}

// xxdPositionals returns the INFILE and OUTFILE operands of xxd's
// arguments (options and their values removed). ok is false when an
// option is missing its value.
func xxdPositionals(args []string) (positionals []string, ok bool) {
	ok = true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(positionals) == 0 && strings.HasPrefix(arg, "-") && arg != "-" {
			if _, takes := xxdValueOptions[arg]; takes {
				// The value may itself start with '-' (`-s -16`).
				if i+1 >= len(args) {
					return positionals, false
				}
				i++
			}
			// Any other dash word is a flag or an option with its value
			// attached (-c8, -s+16).
			continue
		}
		positionals = append(positionals, arg)
	}
	return positionals, ok
}

// xxdWritesOutput reports xxd arguments with an OUTFILE operand (or a
// grammar that cannot be read), so a find or xargs that hands entries to
// such an xxd may change what it names (GAP-2302).
func xxdWritesOutput(args []string) bool {
	positionals, ok := xxdPositionals(args)
	return !ok || len(positionals) > 1
}
