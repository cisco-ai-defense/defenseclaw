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

// FileReader reads the whole text of the program file name for the reach the
// caller has (the hook client reads as the user, in or beside the working
// folder). ok is false for a file it cannot read: a missing or special file
// (-f -, /dev/stdin), one over its size cap, or one outside its reach.
type FileReader func(name string) (text string, ok bool)

// Call is an awk argv and what the caller knows about each word of it.
type Call struct {
	// Words are the words of the call, Words[0] the awk program. A word that
	// expands at run time has no known value.
	Words []string
	// Dynamic[i] reports that Words[i] expands at run time (a variable, a
	// command substitution); Prefix[i] is the text it starts with before its
	// first expansion. Both may be shorter than Words, or nil: a word with
	// no entry is static.
	Dynamic []bool
	Prefix  []string
	// Holed[i] is Words[i] with Hole in the place of each expansion. A
	// program word that expands is read from it: the text around the holes is
	// the program awk gets, and the holes are the part the reading cannot
	// know.
	Holed []string
	// Files reads a -f, --file, -E, --exec or -W exec program file. Nil means
	// the caller has no reach to a file: the program files are then neither
	// read nor reported; a caller with a reach (the hook client) passes one,
	// and a file it cannot read makes the call unknown.
	Files FileReader
}

// Reading is what a call runs through its command channels.
type Reading struct {
	// Body is the shell script of the commands the programs run when each is
	// a literal (ShellBody); empty when no program starts a literal command.
	Body string
	// Dynamic reports a command, program or program file the reading cannot
	// know: the callers answer it at the unknown tier (DynamicReason).
	Dynamic bool
	// Truncated reports a program longer than MaxProgramBytes: what comes
	// before the cap is read, the rest is unknown (the one bound rule).
	Truncated bool
	// Unread reports a program file the caller's Files reader could not read.
	Unread bool
	// Files counts the program files the call names (-f, --file, -E, --exec,
	// -W exec), whether or not the caller could read them.
	Files int
}

func (c Call) dynamic(i int) bool { return i < len(c.Dynamic) && c.Dynamic[i] }

// text is the part of Words[i] known before any expansion.
func (c Call) text(i int) string {
	if !c.dynamic(i) {
		return c.Words[i]
	}
	if i < len(c.Prefix) {
		return c.Prefix[i]
	}
	return ""
}

// callOption names a value option of an awk, beyond OptionValue: the gawk -E
// (--exec) program file, and the mawk -W options, whose value is the next
// word or attached.
func callOption(word string) (name, value string, attached bool) {
	if name, value, attached = OptionValue(word); name != "" {
		return name, value, attached
	}
	switch {
	case word == "-E" || word == "--exec":
		return "E", "", false
	case strings.HasPrefix(word, "--exec="):
		return "E", word[len("--exec="):], true
	case strings.HasPrefix(word, "-E"):
		return "E", word[2:], true
	case word == "-W":
		return "W", "", false
	case strings.HasPrefix(word, "-W"):
		return "W", word[2:], true
	}
	return "", "", false
}

// execOption reports the mawk -W option that reads the program from the next
// word; mawk accepts any prefix of an option name.
func execOption(value string) bool {
	return value != "" && strings.HasPrefix("exec", value)
}

// Hole stands for an expansion in the text of a computed word.
const Hole = "__dchole__"

type callPrograms struct {
	texts []string
	// holed are the indexes of the texts that hold a Hole: a program with a
	// computed part.
	holed []int
	// unknown: a program the call runs is not known (a computed word where
	// the program or its file is, a file that cannot be read).
	unknown bool
	// unread: a program file was not read.
	unread bool
	// files counts the program files the call names.
	files int
}

// readFile reads the program file value of a call.
func (c Call) readFile(value string, dynamic bool, out *callPrograms) {
	out.files++
	switch {
	case dynamic:
		out.unknown, out.unread = true, true
	case c.Files == nil:
	default:
		text, ok := c.Files(value)
		if !ok {
			out.unknown, out.unread = true, true
			return
		}
		out.texts = append(out.texts, text)
	}
}

// guessAll reads every word as program text: an option this reading does not
// know may hide the program, so any later word can be it.
func (c Call) guessAll() callPrograms {
	var out callPrograms
	for i := 1; i < len(c.Words); i++ {
		if c.dynamic(i) {
			out.unknown = true
			if prefix := c.text(i); prefix != "" {
				out.texts = append(out.texts, prefix)
			}
			continue
		}
		out.texts = append(out.texts, c.Words[i])
	}
	return out
}

// programs is the program text of the call: the program operand, the -e
// sources, and the text of the program files the reader reads. A computed
// word where the program or its file is makes the call unknown; a computed
// word anywhere else (an input operand, a -v value) is not program text.
func (c Call) programs() callPrograms {
	var out callPrograms
	supplied := false
	options := true
	for i := 1; i < len(c.Words); i++ {
		dynamic, text := c.dynamic(i), c.text(i)
		if options && !dynamic && text == "--" {
			options = false
			continue
		}
		if options && text != "-" && strings.HasPrefix(text, "-") {
			name, value, attached := callOption(text)
			if name == "" {
				if !dynamic && slices.Contains(HarmlessFlags, text) {
					continue
				}
				return c.guessAll()
			}
			valueDynamic := dynamic
			switch {
			case dynamic:
				// The word is computed after its option letters: the value
				// is whatever it expands to.
			case !attached:
				i++
				if i >= len(c.Words) {
					return c.guessAll()
				}
				value, valueDynamic = c.Words[i], c.dynamic(i)
			}
			switch name {
			case "e":
				supplied = true
				if valueDynamic {
					out.unknown = true
					if prefix := value; prefix != "" && dynamic {
						out.texts = append(out.texts, prefix)
					}
				} else {
					out.texts = append(out.texts, value)
				}
			case "f":
				supplied = true
				c.readFile(value, valueDynamic, &out)
			case "E":
				supplied = true
				c.readFile(value, valueDynamic, &out)
				options = false
			case "W":
				if valueDynamic {
					out.unknown = true
					continue
				}
				if !execOption(value) {
					return c.guessAll()
				}
				i++
				if i >= len(c.Words) {
					return c.guessAll()
				}
				supplied = true
				c.readFile(c.Words[i], c.dynamic(i), &out)
				options = false
			}
			continue
		}
		if !supplied {
			if dynamic {
				// A program with a computed part: read the text around the
				// holes. A program that is one hole, or whose text starts a
				// command, runs code the reading does not know.
				holed := ""
				if i < len(c.Holed) {
					holed = c.Holed[i]
				}
				if holed == "" || holed == Hole {
					out.unknown = true
				} else {
					out.holed = append(out.holed, len(out.texts))
					out.texts = append(out.texts, holed)
				}
			} else {
				out.texts = append(out.texts, c.Words[i])
			}
			supplied = true
		}
		options = false
	}
	if !supplied && out.texts == nil && !out.unknown && len(c.Words) > 1 {
		return c.guessAll()
	}
	return out
}

// Read reads the call: the shell commands its programs run as literals, and
// whether some command is not fully known (built from fields or variables, a
// gawk directive, a program text that does not scan, a program word or file
// the reading cannot know, a program past the byte cap).
func (c Call) Read() Reading {
	commands, reading := c.commands()
	body, unreadable := ShellBody(commands)
	reading.Body = body
	reading.Dynamic = reading.Dynamic || unreadable
	return reading
}

// commands are the literal commands the programs of the call run, with the
// Reading flags but no Body.
func (c Call) commands() (commands []string, reading Reading) {
	programs := c.programs()
	reading = Reading{Dynamic: programs.unknown, Unread: programs.unread, Files: programs.files}
	for index, text := range programs.texts {
		program := Parse(text)
		more, dynamic := program.Commands()
		if slices.Contains(programs.holed, index) {
			// A program with a computed part: a command with a hole in it is
			// not known, and a program that starts any command may start
			// another through the hole.
			more = slices.DeleteFunc(slices.Clone(more), func(command string) bool { return strings.Contains(command, Hole) })
			dynamic = dynamic || program.RunsCommand()
		}
		commands = append(commands, more...)
		reading.Dynamic = reading.Dynamic || dynamic
		reading.Truncated = reading.Truncated || program.Truncated
	}
	return commands, reading
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
