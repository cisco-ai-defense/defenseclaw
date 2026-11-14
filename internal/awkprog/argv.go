// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package awkprog

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// HarmlessFlags are the flags that take no value and add no file or command
// effect. Every other option (gawk -o, -p, -d, -D, -i, -l, ...) leaves the
// program unknown.
var HarmlessFlags = []string{"--posix", "-P", "--traditional", "--compat", "--sandbox", "-S",
	"-b", "--characters-as-bytes", "-n", "--non-decimal-data", "-N", "--use-lc-numeric",
	"-M", "--bignum", "-O", "--optimize", "-s", "--no-optimize", "-r", "--re-interval"}

// OptionValue names a value option (f, e, v or F) and its attached value.
func OptionValue(word string) (name, value string, attached bool) {
	for _, option := range []struct{ short, long, name string }{
		{"-f", "--file", "f"}, {"-e", "--source", "e"}, {"-v", "--assign", "v"}, {"-F", "--field-separator", "F"},
	} {
		switch {
		case word == option.short || word == option.long:
			return option.name, "", false
		case strings.HasPrefix(word, option.long+"="):
			return option.name, word[len(option.long)+1:], true
		case strings.HasPrefix(word, option.short) && !strings.HasPrefix(word, "--"):
			return option.name, word[len(option.short):], true
		}
	}
	return "", "", false
}

// ProgramWords is the inline program text of an awk argv (words[0] is the
// program name): the program operand, or the -e source texts. supplied
// reports that the words already hold the whole program (an inline program
// operand, or a -f or -e option): a later word is then an input operand, an
// assignment or another -f program, none of which changes the program text
// already read (GAP-2172, GAP-0498). An option this reading does not know
// leaves the program unknown (nil, false). A -f program file is separate
// code a caller reads itself.
func ProgramWords(words []string) (programs []string, supplied bool) {
	options := true
	for i := 1; i < len(words); i++ {
		word := words[i]
		if options && word == "--" {
			options = false
			continue
		}
		if options && word != "-" && strings.HasPrefix(word, "-") {
			name, value, attached := OptionValue(word)
			if name == "" {
				if slices.Contains(HarmlessFlags, word) {
					continue
				}
				return nil, false
			}
			if !attached {
				i++
				if i >= len(words) {
					return nil, false
				}
				value = words[i]
			}
			if name == "f" || name == "e" {
				supplied = true
				if name == "e" {
					programs = append(programs, value)
				}
			}
			continue
		}
		if !supplied {
			programs = append(programs, word)
			supplied = true
		}
		options = false
	}
	return programs, supplied
}

// ArgvPrograms are the inline program texts of an awk argv. An option this
// reading does not know leaves the program unknown: any later word can be the
// program, so each one is read as program text. An argv that reads its
// program from a file (-f) has no inline text for that program: the caller
// that reads the file adds its text.
func ArgvPrograms(words []string) []string {
	programs, supplied := ProgramWords(words)
	if programs == nil && !supplied && len(words) > 1 {
		return words[1:]
	}
	return programs
}

// ProgramsCommands are the shell commands the programs run, and whether some
// command is not fully known (built from fields or variables, a gawk
// directive, or program text that does not scan).
func ProgramsCommands(programs []string) (commands []string, dynamic bool) {
	for _, program := range programs {
		more, d := Parse(program).Commands()
		commands = append(commands, more...)
		dynamic = dynamic || d
	}
	return commands, dynamic
}

// ShellBody is the shell script that runs the commands of an awk program as
// the hook would run them directly: the one command itself, or the commands
// each in a subshell on its own line (awk starts each in its own shell, so
// no command sees the directory change or assignment of another). A command
// with no text is skipped. A command that does not parse as shell is left out
// and reported: awk's shell may read it differently from the reader here, so
// the caller treats it as a command it cannot read.
func ShellBody(commands []string) (body string, unreadable bool) {
	var texts []string
	for _, command := range commands {
		if strings.TrimSpace(command) == "" {
			continue
		}
		if _, err := syntax.NewParser().Parse(strings.NewReader(command), ""); err != nil {
			unreadable = true
			continue
		}
		texts = append(texts, command)
	}
	switch len(texts) {
	case 0:
		return "", unreadable
	case 1:
		return texts[0], unreadable
	}
	var b strings.Builder
	for i, text := range texts {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("( " + text + "\n)")
	}
	return b.String(), unreadable
}

// ProgramsShell is the shell script the programs run through their command
// channels (ShellBody of ProgramsCommands), and whether some command of them
// is not fully known: built from anything but string literals, or text the
// shell reader cannot parse.
func ProgramsShell(programs []string) (body string, dynamic bool) {
	commands, dynamic := ProgramsCommands(programs)
	body, unreadable := ShellBody(commands)
	return body, dynamic || unreadable
}

// ArgvShell is ProgramsShell of the inline programs of an awk argv.
func ArgvShell(words []string) (body string, dynamic bool) {
	return ProgramsShell(ArgvPrograms(words))
}
