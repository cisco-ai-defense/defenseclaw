// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// CommandPathWord is one static word of a POSIX shell command that may name
// a path: an argument of a simple command (the value of a --name=VALUE
// option), or the target of a file redirect, also inside the static body of
// an eval or of a shell's -c. Text is the word as the command spells it (its
// source bytes), Value its static value (quotes taken out, a leading ~/ or
// $HOME expanded with the home given).
type CommandPathWord struct {
	Text, Value string
	// FollowsLink is set where the command opens the file the word names,
	// so a link that is the word's last component is followed (cat, cp,
	// a redirect, cd); clear where it acts on the name itself (rm, mv, ln,
	// ls, stat, readlink, find, test, a cp or tar that keeps links).
	FollowsLink bool
	// Program is set for the program word of a simple command.
	Program    bool
	start, end int  // the byte offsets of Text in the command
	quote      byte // 0 at the top level; ' or " inside a quoted body
}

// maxCommandPathBodyDepth is how deep CommandPathWords reads eval and -c
// bodies inside each other: the depth the action analysis reads nested shell
// strings to (actionfacts maxNestedShellStrings).
const maxCommandPathBodyDepth = 4

// CommandPathWords returns the static path words of a POSIX shell command
// in the order they appear. A word with an expansion, a pattern, a ~user or
// no value, and an option word, are not path words. Every word of the
// command is read: a caller that walks the words in the file system bounds
// its work by the distinct words (LocalCommandWordPlaces).
func CommandPathWords(command, home string) []CommandPathWord {
	var words []CommandPathWord
	commandPathWordsIn(command, 0, 0, 0, home, &words)
	slices.SortFunc(words, func(a, b CommandPathWord) int { return a.start - b.start })
	return words
}

func commandPathWordsIn(text string, base int, quote byte, depth int, home string, words *[]CommandPathWord) {
	file, ok := shellparse.Parse(text)
	if !ok {
		return
	}
	add := func(word *syntax.Word, follows, program bool) {
		if word == nil {
			return
		}
		value, static := StaticWord(word, home)
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if !static || value == "" || end > len(text) || start >= end {
			return
		}
		if strings.HasPrefix(value, "--") {
			// --name=VALUE: only a plain literal maps its value's bytes to
			// the source one to one.
			name, rest, found := strings.Cut(value, "=")
			if _, plain := plainLiteralWord(word); !plain || !found || rest == "" {
				return
			}
			start += len(name) + 1
			value = rest
		} else if strings.HasPrefix(value, "-") {
			return
		}
		if strings.HasPrefix(value, "~") || strings.ContainsAny(value, "\x00\r\n") {
			return
		}
		*words = append(*words, CommandPathWord{
			Text: text[start:end], Value: value, FollowsLink: follows, Program: program,
			start: base + start, end: base + end, quote: quote,
		})
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.Stmt:
			for _, redirect := range node.Redirs {
				switch redirect.Op {
				case syntax.RdrOut, syntax.AppOut, syntax.RdrIn, syntax.RdrInOut, syntax.RdrClob,
					syntax.RdrAll, syntax.AppAll:
					add(redirect.Word, true, false)
				}
			}
		case *syntax.CallExpr:
			program := ""
			if len(node.Args) > 0 {
				if value, static := StaticWord(node.Args[0], home); static {
					program = programBase(value)
				}
			}
			follows := commandFollowsOperandLinks(program, node.Args, home)
			for index, arg := range node.Args {
				add(arg, index == 0 || follows, index == 0)
			}
			if depth < maxCommandPathBodyDepth {
				for _, body := range staticCommandBodies(program, node.Args) {
					commandPathWordsIn(body.text, base+body.offset, body.quote, depth+1, home, words)
				}
			}
		}
		return true
	})
}

// commandFollowsOperandLinks reports a program that opens the files its
// operands name, so a link that is an operand is followed; false for one
// that acts on the link itself.
func commandFollowsOperandLinks(program string, args []*syntax.Word, home string) bool {
	switch program {
	case "sed", "gsed":
		// sed -i writes a new file in place of the name: a link there is
		// replaced and its target left alone, unless --follow-symlinks
		// (sedFollowsInPlaceLinks). Without -i sed only reads.
		if !commandHasFlag(args, home, 'i', "--in-place") && !commandHasLongPrefix(args, home, "--in-place=") {
			return true
		}
		words := make([]string, 0, len(args))
		for _, arg := range args {
			value, _ := StaticWord(arg, home)
			words = append(words, value)
		}
		return sedFollowsInPlaceLinks(words)
	case "rm", "unlink", "mv", "ln", "ls", "stat", "lstat", "readlink", "find", "test", "[", "file",
		"rsync", "git", "lsattr":
		return false
	case "chown", "chgrp", "touch":
		return !commandHasFlag(args, home, 'h', "--no-dereference")
	case "cp", "gcp":
		return !commandHasFlag(args, home, 'P', "--no-dereference") && !commandHasFlag(args, home, 'd', "") &&
			!commandHasFlag(args, home, 'a', "--archive") && !commandHasFlag(args, home, 'R', "--recursive") &&
			!commandHasFlag(args, home, 'r', "") ||
			commandHasFlag(args, home, 'L', "--dereference") || commandHasFlag(args, home, 'H', "")
	case "tar", "zip":
		return commandHasFlag(args, home, 'h', "--dereference")
	}
	return true
}

// commandHasFlag reports a short flag in a bundle (-rP) or the long option.
func commandHasFlag(args []*syntax.Word, home string, short byte, long string) bool {
	for _, arg := range args[min(1, len(args)):] {
		value, static := StaticWord(arg, home)
		switch {
		case !static:
			continue
		case value == "--":
			return false
		case long != "" && value == long:
			return true
		case len(value) > 1 && value[0] == '-' && value[1] != '-' && strings.IndexByte(value[1:], short) >= 0:
			return true
		}
	}
	return false
}

// commandHasLongPrefix reports a long option written with its value
// (--in-place=.bak).
func commandHasLongPrefix(args []*syntax.Word, home, prefix string) bool {
	for _, arg := range args[min(1, len(args)):] {
		value, static := StaticWord(arg, home)
		switch {
		case !static:
			continue
		case value == "--":
			return false
		case strings.HasPrefix(value, prefix):
			return true
		}
	}
	return false
}

type staticCommandBody struct {
	text   string
	offset int
	quote  byte
}

// staticCommandBodies returns the bodies an eval runs, or a shell runs after
// -c, that the source spells as one single-quoted or plain double-quoted
// string: their bytes are the body's bytes, so a word of the body has a
// place in the command.
func staticCommandBodies(program string, args []*syntax.Word) []staticCommandBody {
	var candidates []*syntax.Word
	switch program {
	case "eval":
		candidates = args[1:]
	case "sh", "bash", "dash", "zsh", "ksh", "ash", "busybox":
		for index := 1; index+1 < len(args); index++ {
			flag, plain := plainLiteralWord(args[index])
			if plain && strings.HasPrefix(flag, "-") && !strings.HasPrefix(flag, "--") && strings.Contains(flag, "c") {
				candidates = args[index+1 : index+2]
				break
			}
		}
	}
	var bodies []staticCommandBody
	for _, word := range candidates {
		if word == nil || len(word.Parts) != 1 {
			continue
		}
		switch part := word.Parts[0].(type) {
		case *syntax.SglQuoted:
			if !part.Dollar {
				bodies = append(bodies, staticCommandBody{text: part.Value, offset: int(part.Pos().Offset()) + 1, quote: '\''})
			}
		case *syntax.DblQuoted:
			if part.Dollar || len(part.Parts) != 1 {
				continue
			}
			if lit, ok := part.Parts[0].(*syntax.Lit); ok && !strings.ContainsAny(lit.Value, "\\$`") {
				bodies = append(bodies, staticCommandBody{text: lit.Value, offset: int(part.Pos().Offset()) + 1, quote: '"'})
			}
		}
	}
	return bodies
}

// CommandWordPlace is where a command word's path lies in the file system
// it runs in: Followed with every link followed, the last component too;
// Entry with its folders followed and its last name kept. Either is empty
// when it is the place the word spells.
type CommandWordPlace struct {
	Followed, Entry string
}

// LinkResolvedCommand returns command with each word CommandPathWords finds
// whose Text has a place in places spelled as that place (Followed where the
// command follows the word's link, else Entry): the command as the shell runs
// it once the file system has resolved its links. A place that the word's
// quoting cannot carry as it is, and a word inside a word already replaced,
// are left as written. changed is false when no word was replaced.
func LinkResolvedCommand(command, home string, places map[string]CommandWordPlace) (string, bool) {
	if len(places) == 0 {
		return command, false
	}
	var out strings.Builder
	at, changed := 0, false
	for _, word := range CommandPathWords(command, home) {
		place, found := places[word.Text]
		if !found || word.start < at {
			continue
		}
		target := place.Entry
		if word.FollowsLink {
			target = place.Followed
		}
		if !path.IsAbs(target) || path.Clean(target) != target {
			continue
		}
		spelled, ok := shellPathSpelling(target, word.quote)
		if !ok {
			continue
		}
		out.WriteString(command[at:word.start])
		out.WriteString(spelled)
		at, changed = word.end, true
	}
	if !changed {
		return command, false
	}
	out.WriteString(command[at:])
	return out.String(), true
}

// shellPathSpelling spells an absolute path as one shell word: as it is when
// it holds only plain path bytes, else single-quoted at the top level. Inside
// a quoted body only the plain spelling keeps both readings the same.
func shellPathSpelling(target string, quote byte) (string, bool) {
	plain := true
	for i := 0; i < len(target); i++ {
		c := target[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == '/', c == '-', c == ',', c == ':', c == '@', c == '%', c == '+':
		default:
			plain = false
		}
	}
	switch {
	case plain:
		return target, true
	case quote != 0 || strings.ContainsAny(target, "\x00\r\n"):
		return "", false
	}
	return "'" + strings.ReplaceAll(target, "'", `'\''`) + "'", true
}
