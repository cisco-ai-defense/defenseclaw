// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// fileOptionRole says what an option's value is.
type fileOptionRole int

const (
	// fileOptionValue: the value is data (a count, a delimiter, a key).
	fileOptionValue fileOptionRole = iota
	// fileOptionReadsFile: the value names a file the program reads.
	fileOptionReadsFile
	// fileOptionWritesFile: the value names a file the program writes.
	fileOptionWritesFile
	// fileOptionRunsProgram: the value names a program the tool starts.
	fileOptionRunsProgram
)

// fileReaderSpec is the option table of one standard program that reads the
// files named in its arguments (cat, head and the programs below). The table
// is the whole grammar: which options take a value, and which of those
// values are themselves a file.
type fileReaderSpec struct {
	// short: option letters that take a value (the rest of the word, or the
	// next word). Letters are case sensitive (sort -s is a switch, -S a value).
	short map[byte]fileOptionRole
	// long: long options that take a value (--name=value or --name value).
	// A unique prefix of a name stands for it, as in GNU getopt_long.
	long map[string]fileOptionRole
	// operandsAreFiles: every non-option word is a file the program reads.
	operandsAreFiles bool
	// startsProgram: the first non-option word is a program the tool starts
	// (xargs), not a file; the program is read on its own words.
	startsProgram bool
}

func fileOptions(letters string, role fileOptionRole, into map[byte]fileOptionRole) map[byte]fileOptionRole {
	if into == nil {
		into = make(map[byte]fileOptionRole, len(letters))
	}
	for i := 0; i < len(letters); i++ {
		into[letters[i]] = role
	}
	return into
}

func longFileOptions(role fileOptionRole, into map[string]fileOptionRole, names ...string) map[string]fileOptionRole {
	if into == nil {
		into = make(map[string]fileOptionRole, len(names))
	}
	for _, name := range names {
		into[name] = role
	}
	return into
}

// posixFileReaderSpecs is the "reads its file operands" table: one row per
// program. A row is the program's own option grammar from its manual page
// (GNU coreutils, util-linux hexdump, GNU binutils strings, GNU findutils
// xargs); an option not listed is a switch.
var posixFileReaderSpecs = map[string]fileReaderSpec{
	"tac": {
		short:            fileOptions("s", fileOptionValue, nil),
		long:             longFileOptions(fileOptionValue, nil, "separator"),
		operandsAreFiles: true,
	},
	"nl": {
		short: fileOptions("bdfhilnsvw", fileOptionValue, nil),
		long: longFileOptions(fileOptionValue, nil,
			"body-numbering", "section-delimiter", "footer-numbering",
			"header-numbering", "line-increment", "join-blank-lines",
			"number-format", "number-separator", "starting-line-number",
			"number-width"),
		operandsAreFiles: true,
	},
	"od": {
		short: fileOptions("AjNSt", fileOptionValue, nil),
		long: longFileOptions(fileOptionValue, nil,
			"address-radix", "skip-bytes", "read-bytes", "format"),
		operandsAreFiles: true,
	},
	"strings": {
		short: fileOptions("ntesT", fileOptionValue, nil),
		long: longFileOptions(fileOptionValue, nil,
			"bytes", "radix", "encoding", "target", "output-separator"),
		operandsAreFiles: true,
	},
	"cut": {
		short: fileOptions("bcdf", fileOptionValue, nil),
		long: longFileOptions(fileOptionValue, nil,
			"bytes", "characters", "delimiter", "fields", "output-delimiter"),
		operandsAreFiles: true,
	},
	"sort": {
		short: fileOptions("o", fileOptionWritesFile, fileOptions("ktST", fileOptionValue, nil)),
		long: longFileOptions(fileOptionValue,
			longFileOptions(fileOptionWritesFile,
				longFileOptions(fileOptionReadsFile,
					longFileOptions(fileOptionRunsProgram, nil, "compress-program"),
					"random-source", "files0-from"),
				"output"),
			"key", "field-separator", "buffer-size", "temporary-directory",
			"parallel", "batch-size", "sort"),
		operandsAreFiles: true,
	},
	"hexdump": {
		short: fileOptions("f", fileOptionReadsFile, fileOptions("ens", fileOptionValue, nil)),
		long: longFileOptions(fileOptionReadsFile,
			longFileOptions(fileOptionValue, nil, "format", "length", "skip"),
			"format-file"),
		operandsAreFiles: true,
	},
	"xargs": {
		short: fileOptions("a", fileOptionReadsFile,
			fileOptions("dEILnPs", fileOptionValue, nil)),
		long: longFileOptions(fileOptionReadsFile,
			longFileOptions(fileOptionValue, nil,
				"delimiter", "max-args", "max-procs", "max-chars",
				"process-slot-var"),
			"arg-file"),
		startsProgram: true,
	},
	// diff (GNU diffutils): both operands are read, as are the files its
	// -S, -X and --from-file/--to-file options name.
	"diff": {
		short: fileOptions("SX", fileOptionReadsFile,
			fileOptions("xILUCWFD", fileOptionValue, nil)),
		long: longFileOptions(fileOptionReadsFile,
			longFileOptions(fileOptionValue, nil,
				"exclude", "label", "ignore-matching-lines", "show-function-line", "width"),
			"starting-file", "exclude-from", "from-file", "to-file"),
		operandsAreFiles: true,
	},
}

// classifyPOSIXFileReader records the files a standard reader program reads
// (its file operands and the files its options name) and the file its
// -o/--output option writes. A program that starts a helper program
// (sort --compress-program) keeps the parse partial.
func classifyPOSIXFileReader(out *parseOutput, command *CommandFact, spec fileReaderSpec) {
	if !command.ArgvComplete {
		out.markPartial(IssueDynamicWord)
	}
	argv := command.Argv
	apply := func(role fileOptionRole, value string) {
		switch role {
		case fileOptionReadsFile:
			addOperation(command, OperationRead)
			appendCommandPath(out, command, PathAccessRead, value)
		case fileOptionWritesFile:
			addOperation(command, OperationWrite)
			appendCommandPath(out, command, PathAccessWrite, value)
		case fileOptionRunsProgram:
			out.markPartial(IssueUnsupportedConstruct)
		}
	}
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case options && arg == "--":
			options = false
		case options && len(arg) > 2 && strings.HasPrefix(arg, "--"):
			key, value, joined := strings.Cut(arg[2:], "=")
			name, ok := spec.longOption(key)
			if !ok {
				continue
			}
			if !joined {
				if i+1 >= len(argv) {
					out.markPartial(IssueUnknownOperandGrammar)
					continue
				}
				i++
				value = argv[i]
			}
			apply(spec.long[name], value)
		case options && len(arg) > 1 && arg[0] == '-':
			// A cluster of switches ends at the first letter that takes a
			// value: the rest of the word, or the next word (-rk 2, -d,).
			for j := 1; j < len(arg); j++ {
				role, takes := spec.short[arg[j]]
				if !takes {
					continue
				}
				value := arg[j+1:]
				if value == "" {
					if i+1 >= len(argv) {
						out.markPartial(IssueUnknownOperandGrammar)
						break
					}
					i++
					value = argv[i]
				}
				apply(role, value)
				break
			}
		case !spec.operandsAreFiles:
			// The first operand of xargs starts the program it runs.
			return
		default:
			addOperation(command, OperationRead)
			appendCommandPath(out, command, PathAccessRead, arg)
		}
	}
}

// longOption resolves a long option name, or a unique prefix of one.
func (spec fileReaderSpec) longOption(key string) (string, bool) {
	if _, ok := spec.long[key]; ok {
		return key, true
	}
	found := ""
	for name := range spec.long {
		if strings.HasPrefix(name, key) {
			if found != "" {
				return "", false
			}
			found = name
		}
	}
	return found, found != "" && key != ""
}
